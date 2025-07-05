def generate_setup(DOMAIN_NAME, ADMIN_EMAIL, ADMIN_PASSWORD, PORT, VOLUME_DIR="/opt/code-server", DNS_HOOK_SCRIPT="/usr/local/bin/dns-hook-script.sh"):
    script_template = f"""#!/bin/bash
set -e

# ========== VALIDATION ==========
echo "[1/10] Validating inputs..."

# Validate domain
if [[ ! "{DOMAIN_NAME}" =~ ^[a-zA-Z0-9.-]+\\.[a-zA-Z]{{2,}}$ ]]; then
    echo "ERROR: Invalid domain format"
    exit 1
fi

# Validate port
if [ "{PORT}" -lt 1024 ] || [ "{PORT}" -gt 65535 ]; then
    echo "ERROR: Port {PORT} is not valid (must be 1024-65535)"
    exit 1
fi

# Check if port is in use
if lsof -i :{PORT} > /dev/null; then
    echo "ERROR: Port {PORT} is already in use"
    exit 1
fi

# ========== SYSTEM SETUP ==========
echo "[2/10] Updating system and installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get upgrade -y -q
apt-get install -y -q curl nginx certbot python3-certbot-nginx ufw git build-essential sudo

# ========== INSTALL CODE-SERVER ==========
echo "[3/10] Installing code-server..."
curl -fsSL https://code-server.dev/install.sh | HOME=/root sh

# ========== CREATE SERVICE USER ==========
SERVICE_USER="coder"
echo "[4/10] Creating service user..."
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$SERVICE_USER"
    echo "$SERVICE_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$SERVICE_USER
    chmod 440 /etc/sudoers.d/$SERVICE_USER
fi

# ========== CONFIGURE CODE-SERVER ==========
echo "[5/10] Configuring code-server..."
mkdir -p {VOLUME_DIR}/config

cat > {VOLUME_DIR}/config/config.yaml <<EOF
bind-addr: 0.0.0.0:{PORT}
auth: password
password: {ADMIN_PASSWORD}
cert: false
EOF

chown -R $SERVICE_USER:$SERVICE_USER {VOLUME_DIR}
chmod 700 {VOLUME_DIR}/config
chmod 600 {VOLUME_DIR}/config/config.yaml

mkdir -p /home/$SERVICE_USER/.config
ln -sf {VOLUME_DIR}/config /home/$SERVICE_USER/.config/code-server

# ========== SYSTEMD AUTO-RESTART ==========
echo "[6/10] Enabling systemd auto-restart..."
mkdir -p /etc/systemd/system/code-server@.service.d
cat > /etc/systemd/system/code-server@.service.d/override.conf <<EOF
[Service]
Restart=on-failure
RestartSec=5s
EOF

systemctl daemon-reexec
systemctl daemon-reload
systemctl enable --now code-server@$SERVICE_USER

if ! systemctl is-active --quiet code-server@$SERVICE_USER; then
    echo "ERROR: code-server service failed to start"
    journalctl -u code-server@$SERVICE_USER -b --no-pager -n 10
    exit 1
fi

# ========== FIREWALL ==========
echo "[7/10] Configuring firewall..."
ufw allow OpenSSH
ufw allow 80,443/tcp
ufw allow {PORT}/tcp
ufw --force enable

# ========== TEMPORARY NGINX CONFIG (HTTP ONLY) ==========
echo "[8/10] Configuring temporary Nginx (HTTP only)..."
rm -f /etc/nginx/sites-enabled/default

cat > /etc/nginx/sites-available/code-server <<EOF
server {{
    listen 80;
    server_name {DOMAIN_NAME};

    location / {{
        proxy_pass http://localhost:{PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_http_version 1.1;
    }}
}}
EOF

ln -sf /etc/nginx/sites-available/code-server /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# ========== SSL SETUP ==========
echo "[9/10] Setting up SSL certificate..."
mkdir -p /etc/letsencrypt
mkdir -p /etc/letsencrypt/ssl-dhparams

# Download recommended TLS parameters
if [ ! -f "/etc/letsencrypt/options-ssl-nginx.conf" ]; then
    curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf > /etc/letsencrypt/options-ssl-nginx.conf
fi

if [ ! -f "/etc/letsencrypt/ssl-dhparams.pem" ]; then
    curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem > /etc/letsencrypt/ssl-dhparams.pem
fi

# Obtain certificate first
if [ -f "{DNS_HOOK_SCRIPT}" ]; then
    echo "Using DNS hook script at {DNS_HOOK_SCRIPT}"
    chmod +x "{DNS_HOOK_SCRIPT}"
    certbot certonly --manual \\
        --preferred-challenges=dns \\
        --manual-auth-hook "{DNS_HOOK_SCRIPT} add" \\
        --manual-cleanup-hook "{DNS_HOOK_SCRIPT} clean" \\
        --agree-tos --email {ADMIN_EMAIL} \\
        -d "{DOMAIN_NAME}" -d "*.{DOMAIN_NAME}" \\
        --non-interactive --manual-public-ip-logging-ok
else
    echo "Using HTTP challenge"
    certbot --nginx -d {DOMAIN_NAME} --non-interactive --agree-tos --email {ADMIN_EMAIL} --no-redirect
fi

# ========== FINAL NGINX CONFIG (HTTPS) ==========
echo "[10/10] Configuring final Nginx (HTTPS)..."
cat > /etc/nginx/sites-available/code-server <<EOF
server {{
    listen 80;
    server_name {DOMAIN_NAME};
    return 301 https://\$host\$request_uri;
}}

server {{
    listen 443 ssl http2;
    server_name {DOMAIN_NAME};

    ssl_certificate /etc/letsencrypt/live/{DOMAIN_NAME}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{DOMAIN_NAME}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    location / {{
        proxy_pass http://localhost:{PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_http_version 1.1;
    }}
}}
EOF

nginx -t && systemctl reload nginx

# ========== DONE ==========
echo "============================================"
echo "✅ code-server Setup Complete!"
echo ""
echo "🌍 Access: https://{DOMAIN_NAME}"
echo "👤 User: $SERVICE_USER"
echo "🔑 Password: (use the one you set in config.yaml)"
echo ""
echo "🛠 Service Commands:"
echo "   systemctl status code-server@$SERVICE_USER"
echo "   systemctl restart code-server@$SERVICE_USER"
echo "   journalctl -u code-server@$SERVICE_USER -f"
echo ""
echo "📁 Files:"
echo "   - Config: {VOLUME_DIR}/config/config.yaml"
echo "   - User home: /home/$SERVICE_USER"
echo ""
echo "🔐 SSL:"
echo "   - Certs: /etc/letsencrypt/live/{DOMAIN_NAME}/"
echo "   - Check: certbot certificates"
echo "============================================"
"""
    return script_template
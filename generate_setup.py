def generate_setup(DOMAIN_NAME, ADMIN_EMAIL, ADMIN_PASSWORD, PORT, VOLUME_DIR="/opt/code-server", DNS_HOOK_SCRIPT="/usr/local/bin/dns-hook-script.sh"):
    SERVICE_USER="coder"
    letsencrypt_options_url = "https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf"
    ssl_dhparams_url = "https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem"
   
    script_template = f"""#!/bin/bash
set -e



# ========== VALIDATION ==========
echo "[1/12] Validating inputs..."
LOG_FILE="/var/log/code-server-install.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Validate domain
if [[ ! "{DOMAIN_NAME}" =~ ^[a-zA-Z0-9.-]+\\.[a-zA-Z]{{2,}}$ ]]; then
    echo "ERROR: Invalid domain format '{DOMAIN_NAME}'"
    exit 1
fi

# Enhanced port validation
if [[ ! "{PORT}" =~ ^[0-9]+$ ]] || [ "{PORT}" -lt 1024 ] || [ "{PORT}" -gt 65535 ]; then
    echo "ERROR: Invalid port number '{PORT}' (must be 1024-65535)"
    exit 1
fi

# Port conflict resolution
if ss -tulnp | grep -q ":{PORT}"; then
    echo "WARNING: Port {PORT} is in use, attempting to resolve..."
    PROCESS_INFO=$(ss -tulnp | grep ":{PORT}")
    echo "Conflict details: $PROCESS_INFO"
    
    # Try to stop conflicting services
    echo "Stopping any existing code-server instances..."
    systemctl stop code-server@{SERVICE_USER} || true
    pkill -f "code-server" || true
    sleep 2
    
    # Final check
    if ss -tulnp | grep -q ":{PORT}"; then
        PID=$(ss -tulnp | grep ":{PORT}" | awk '{{print $7}}' | cut -d= -f2 | cut -d, -f1 | head -1)
        PROCESS_NAME=$(ps -p "$PID" -o comm= 2>/dev/null || echo "unknown")
        echo "ERROR: Could not free port {PORT}"
        echo "Process $PID ($PROCESS_NAME) is still using the port"
        echo "Please manually stop the service and try again"
        exit 1
    else
        echo "Successfully freed port {PORT}"
    fi
fi

# ========== SYSTEM SETUP ==========
echo "[2/12] Updating system and installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get upgrade -y -q
apt-get install -y -q \\
    curl \\
    nginx \\
    certbot \\
    python3-certbot-nginx \\
    ufw \\
    git \\
    build-essential \\
    sudo \\
    cron \\
    python3 \\
    python3-pip \\
    gnupg \\
    software-properties-common \\
    libssl-dev \\
    zlib1g-dev \\
    libbz2-dev \\
    libreadline-dev \\
    libsqlite3-dev \\
    libffi-dev

# ========== NODE.JS INSTALLATION ==========
echo "[3/12] Installing Node.js LTS..."
apt-get remove -y nodejs npm || true
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y -q nodejs

NODE_VERSION=$(node --version)
echo "Node.js version: $NODE_VERSION"

npm install -g npm@latest

# ========== DEVELOPMENT TOOLS ==========
echo "[4/12] Installing development tools..."

echo "Installing Azure CLI..."
curl -sL https://aka.ms/InstallAzureCLIDeb | bash

echo "Installing Netlify CLI..."
npm install -g netlify-cli --force 2>&1 | while read line; do echo "[npm] $line"; done

echo "Installing Yarn..."
npm install -g yarn

# ========== PYENV INSTALLATION ==========
echo "[5/12] Installing pyenv and Python..."
export HOME=/root
if [ -d "$HOME/.pyenv" ]; then
    echo "Found existing pyenv installation, updating..."
    cd "$HOME/.pyenv" && git pull
else
    echo "Installing fresh pyenv..."
    curl -fsSL https://pyenv.run | bash
fi

# Setup pyenv environment for root
cat >> ~/.bashrc <<'EOF'

export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
if command -v pyenv 1>/dev/null 2>&1; then
    eval "$(pyenv init --path)"
    eval "$(pyenv init -)"
fi
EOF

# Source bashrc to get pyenv available in this shell session
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init --path)"
eval "$(pyenv init -)"

apt-get install -y -q make build-essential libssl-dev zlib1g-dev \\
    libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm \\
    libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev

if ! pyenv versions | grep -q 3.9.7; then
    pyenv install 3.9.7 --verbose
fi
pyenv global 3.9.7

PYTHON_VERSION=$(python --version)
echo "Python version: $PYTHON_VERSION"

# ========== ELECTRON DEPENDENCIES ==========
echo "[6/12] Installing Electron dependencies..."
add-apt-repository universe || true
apt-get update -q
apt-get install -y -q \\
    libgtk-3-0 \\
    libnotify4 \\
    libnss3 \\
    libxss1 \\
    libasound2-data \\
    libasound2-plugins \\
    libxtst6 \\
    xauth \\
    xvfb
npm install electron --save-dev

# ========== DOCKER INSTALLATION ==========
echo "[7/12] Installing Docker..."
curl -fsSL https://get.docker.com | sh
usermod -aG docker {SERVICE_USER} || true

# ========== KUBERNETES TOOLS ==========
echo "[8/12] Installing kubectl..."
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
rm kubectl

# ========== TERRAFORM INSTALLATION ==========
echo "[9/12] Installing Terraform..."
curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor --batch --yes -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/hashicorp.list
apt-get update -q
apt-get install -y -q terraform

# ========== CODE-SERVER INSTALLATION ==========
echo "[10/12] Installing code-server..."
curl -fsSL https://code-server.dev/install.sh | HOME=/root sh

# ========== USER SETUP ==========
echo "[11/12] Configuring service user '{SERVICE_USER}'..."
if ! id -u "{SERVICE_USER}" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "{SERVICE_USER}"
    echo "{SERVICE_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/{SERVICE_USER}
    chmod 440 /etc/sudoers.d/{SERVICE_USER}

    # Setup pyenv environment for service user
    su - {SERVICE_USER} -c 'curl -fsSL https://pyenv.run | bash'

    su - {SERVICE_USER} -c 'cat >> ~/.bashrc <<EOF
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
if command -v pyenv 1>/dev/null 2>&1; then
    eval "$(pyenv init --path)"
    eval "$(pyenv init -)"
fi
EOF'

    su - {SERVICE_USER} -c 'export PYENV_ROOT="$HOME/.pyenv"; export PATH="$PYENV_ROOT/bin:$PATH"; eval "$(pyenv init --path)"; eval "$(pyenv init -)"; pyenv install -s 3.9.7; pyenv global 3.9.7'
fi

# ========== CODE-SERVER CONFIG ==========
echo "[12/12] Configuring code-server..."
mkdir -p {VOLUME_DIR}/config

cat > {VOLUME_DIR}/config/config.yaml <<EOF
bind-addr: 0.0.0.0:{PORT}
auth: password
password: {ADMIN_PASSWORD}
cert: false
EOF

chown -R {SERVICE_USER}:{SERVICE_USER} {VOLUME_DIR}
chmod 700 {VOLUME_DIR}/config
chmod 600 {VOLUME_DIR}/config/config.yaml

mkdir -p /home/{SERVICE_USER}/.config
ln -sf {VOLUME_DIR}/config /home/{SERVICE_USER}/.config/code-server

# ========== VSCode EXTENSIONS ==========
echo "Installing VSCode extensions..."
extensions=(
    "ms-azuretools.vscode-azureterraform"
    "ms-azuretools.vscode-azureappservice"
    "ms-azuretools.vscode-azurefunctions"
    "ms-azuretools.vscode-azurestaticwebapps"
    "ms-azuretools.vscode-azurestorage"
    "ms-azuretools.vscode-cosmosdb"
    "ms-azuretools.vscode-docker"
    "ms-kubernetes-tools.vscode-kubernetes-tools"
    "netlify.netlify-vscode"
    "dbaeumer.vscode-eslint"
    "esbenp.prettier-vscode"
    "ms-vscode.vscode-typescript-next"
    "eamodio.gitlens"
    "ms-vscode-remote.remote-containers"
    "ms-vscode-remote.remote-ssh"
    "ms-vscode.powershell"
    "ms-python.python"
    "ms-toolsai.jupyter"
    "hashicorp.terraform"
    "redhat.vscode-yaml"
)

for extension in "${{extensions[@]}}"; do
    su - {SERVICE_USER} -c "code-server --install-extension $extension"
done

# ========== SERVICE CONFIGURATION ==========
mkdir -p /etc/systemd/system/code-server@.service.d
cat > /etc/systemd/system/code-server@.service.d/override.conf <<EOF
[Service]
Restart=on-failure
RestartSec=5s
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/home/{SERVICE_USER}/.pyenv/shims:/home/{SERVICE_USER}/.pyenv/bin"
EOF

systemctl daemon-reexec
systemctl daemon-reload
systemctl enable --now code-server@{SERVICE_USER}

if ! systemctl is-active --quiet code-server@{SERVICE_USER}; then
    echo "ERROR: code-server service failed to start"
    journalctl -u code-server@{SERVICE_USER} -b --no-pager -n 10
    exit 1
fi

# ========== NETWORK SECURITY ==========
echo "[6/9] Configuring firewall..."
ufw allow 22,80,443,{PORT}/tcp
ufw --force enable

# ========== SSL CERTIFICATE ==========
echo "[7/9] Setting up SSL certificate..."

# Download Let's Encrypt configuration files
mkdir -p /etc/letsencrypt
curl -s "{letsencrypt_options_url}" > /etc/letsencrypt/options-ssl-nginx.conf
curl -s "{ssl_dhparams_url}" > /etc/letsencrypt/ssl-dhparams.pem

if [ -f "$DNS_HOOK_SCRIPT" ]; then
    echo "Using DNS hook script at $DNS_HOOK_SCRIPT"
    chmod +x "$DNS_HOOK_SCRIPT"
    
    # Obtain certificate
    certbot certonly --manual \\
        --preferred-challenges=dns \\
        --manual-auth-hook "$DNS_HOOK_SCRIPT add" \\
        --manual-cleanup-hook "$DNS_HOOK_SCRIPT clean" \\
        --agree-tos --email "{ADMIN_EMAIL}" \\
        -d "{DOMAIN_NAME}" -d "*.{DOMAIN_NAME}" \\
        --non-interactive \\
        --manual-public-ip-logging-ok
else
    echo "Warning: No DNS hook script found at $DNS_HOOK_SCRIPT"
    echo "Falling back to standard certificate"
    certbot --nginx -d "{DOMAIN_NAME}" --non-interactive --agree-tos --email "{ADMIN_EMAIL}" --redirect
fi

# ========== NGINX CONFIG ==========
echo "[8/9] Configuring Nginx..."

# Remove default Nginx config
rm -f /etc/nginx/sites-enabled/default

 
# ========== VERIFICATION ==========
echo "[9/9] Verifying setup..."

# Verify Nginx config
if ! nginx -t; then
    echo "ERROR: Nginx configuration test failed"
    exit 1
fi

# Verify SSL certificate
if [ ! -f "/etc/letsencrypt/live/{DOMAIN_NAME}/fullchain.pem" ]; then
    echo "ERROR: SSL certificate not found!"
    exit 1
fi

# Verify port accessibility
if ! curl -s -o /dev/null -w "%{{http_code}}" http://localhost:{PORT} | grep -q 200; then
    echo "ERROR: Cannot access Forgejo on port {PORT}"
    exit 1
fi

 # Verify services
systemctl is-active --quiet nginx || echo "WARNING: Nginx is not running"
systemctl is-active --quiet code-server@{SERVICE_USER} || echo "WARNING: code-server is not running"

 
# Complete the installation by accessing the web interface
echo "Waiting for vscde to be fully ready..."
until curl -s http://localhost:{PORT} | grep -q "Initial configuration"; do
    sleep 5
done

####SSL CERTIFICATE SETUP WITH NGXIS
$ sudo systemctl restart code-server@coder
sudo systemctl status code-server@coder
$ sudo ss -tulnp | grep :8080
sudo systemctl restart nginx
sudo systemctl status nginx

echo "ngix certbot..."
# Non-interactive input:
# 1) Email = ADMIN_EMAIL
# 2) y, ACME server. Do you agree
# 3) n, EFF news, campaigns, and ways to support digital freedom.
printf '%s\\ny\\ny\\n' "{ADMIN_EMAIL}" | sudo certbot --nginx -d {DOMAIN_NAME}

sudo ls -l /etc/letsencrypt/live/{DOMAIN_NAME}/fullchain.pem

# Remove default nginx config if exists
rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/sites-available/default

# Write nginx config automatically
SSL_DOMAIN_NAME={DOMAIN_NAME}
SSL_PORT={PORT}

cat > /etc/nginx/sites-available/vscode <<EOF
server {{
    listen 80;
    server_name {DOMAIN_NAME};

    return 301 https://\\$host\\$request_uri;
}}

server {{
    listen 443 ssl;
    server_name {DOMAIN_NAME};

    ssl_certificate /etc/letsencrypt/live/{DOMAIN_NAME}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{DOMAIN_NAME}/privkey.pem;

    location / {{
        proxy_pass http://localhost:{PORT}/;
        proxy_set_header Host \\$host;
        proxy_set_header Upgrade \\$http_upgrade;
        proxy_set_header Connection upgrade;
        proxy_set_header Accept-Encoding gzip;
        proxy_set_header X-Real-IP \\$remote_addr;
        proxy_set_header X-Forwarded-For \\$proxy_add_x_forwarded_for;
    }}
}}
EOF


# Enable the site by symlinking
ln -sf /etc/nginx/sites-available/vscode /etc/nginx/sites-enabled/
nginx -t && systemctl restart nginx
 
# ========== VERIFICATION ==========
echo "[9/9] Verifying setup..."

# Verify Nginx config
if ! nginx -t; then
    echo "ERROR: Nginx configuration test failed"
    exit 1
fi

# Verify SSL certificate
if [ ! -f "/etc/letsencrypt/live/{DOMAIN_NAME}/fullchain.pem" ]; then
    echo "ERROR: SSL certificate not found!"
    exit 1
fi

# Verify port accessibility
if ! curl -s -o /dev/null -w "%{{http_code}}" http://localhost:{PORT} | grep -q 200; then
    echo "ERROR: Cannot access vscode on port {PORT}"
    exit 1
fi

# Automate certbot renewal cron job if not already set
CRON_CMD="0 3 * * * /usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx'"
( crontab -l 2>/dev/null | grep -v -F "$CRON_CMD" ; echo "$CRON_CMD" ) | crontab -

# Sudo Permission to coder
sudo chown -R coder:coder /home/coder/.config

 
echo "Setup complete!"
"""
    return script_template

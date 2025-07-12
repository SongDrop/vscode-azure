def generate_setup(DOMAIN_NAME, ADMIN_EMAIL, ADMIN_PASSWORD, PORT, VOLUME_DIR="/opt/code-server", DNS_HOOK_SCRIPT="/usr/local/bin/dns-hook-script.sh"):
    SERVICE_USER = "coder"
    letsencrypt_options_url = "https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf"
    ssl_dhparams_url = "https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem"

    script_template = f"""#!/bin/bash
set -e

# ========== VALIDATION ==========
echo "[1/20] Validating inputs..."
LOG_FILE="/var/log/code-server-install.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Validate domain
if [[ ! "{DOMAIN_NAME}" =~ ^[a-zA-Z0-9.-]+\\.[a-zA-Z]{{2,}}$ ]]; then
    echo "ERROR: Invalid domain format '{DOMAIN_NAME}'"
    exit 1
fi

# Validate port
if [[ ! "{PORT}" =~ ^[0-9]+$ ]] || [ "{PORT}" -lt 1024 ] || [ "{PORT}" -gt 65535 ]; then
    echo "ERROR: Invalid port number '{PORT}' (must be 1024-65535)"
    exit 1
fi

# Port conflict resolution
if ss -tulnp | grep -q ":{PORT}"; then
    echo "WARNING: Port {PORT} is in use, attempting to resolve..."
    PROCESS_INFO=$(ss -tulnp | grep ":{PORT}")
    echo "Conflict details: $PROCESS_INFO"
    systemctl stop code-server@{SERVICE_USER} || true
    pkill -f "code-server" || true
    sleep 2
    if ss -tulnp | grep -q ":{PORT}"; then
        PID=$(ss -tulnp | grep ":{PORT}" | awk '{{print $7}}' | cut -d= -f2 | cut -d, -f1 | head -1)
        PROCESS_NAME=$(ps -p "$PID" -o comm= 2>/dev/null || echo "unknown")
        echo "ERROR: Could not free port {PORT}, process $PID ($PROCESS_NAME) still using it"
        exit 1
    else
        echo "Successfully freed port {PORT}"
    fi
fi

# ========== SYSTEM SETUP ==========
echo "[2/20] Updating system and installing dependencies..."
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

# ========== PYTHON ==========
echo "[5/20] Installing pyenv and Python..."
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

# ========== ELECTRON ==========
echo "[6/20] Installing Electron dependencies..."
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

# ========== DOCKER ==========
echo "[7/20] Installing Docker..."
curl -fsSL https://get.docker.com | sh
usermod -aG docker {SERVICE_USER} || true

# ========== KUBERNETES ==========
echo "[8/20] Installing kubectl..."
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
rm kubectl

# ========== TERRAFORM ==========
echo "[9/20] Installing Terraform..."
curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor --batch --yes -o /usr/share/keyrings/hashicorp.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list
apt-get update -q && apt-get install -y terraform

# ========== CODE-SERVER ==========
echo "[10/20] Installing code-server..."
curl -fsSL https://code-server.dev/install.sh | HOME=/root sh

# ========== USER SETUP ==========
echo "[11/20] Creating user '{SERVICE_USER}'..."
id -u {SERVICE_USER} &>/dev/null || useradd -m -s /bin/bash {SERVICE_USER}
echo "{SERVICE_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/{SERVICE_USER}
chmod 440 /etc/sudoers.d/{SERVICE_USER}
su - {SERVICE_USER} -c 'curl -fsSL https://pyenv.run | bash'
su - {SERVICE_USER} -c 'export PYENV_ROOT="$HOME/.pyenv"; export PATH="$PYENV_ROOT/bin:$PATH"; eval "$(pyenv init --path)"; eval "$(pyenv init -)"; pyenv install -s 3.9.7; pyenv global 3.9.7'

# ========== CONFIG ==========
echo "[12/20] Configuring code-server..."
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

# ========== EXTENSIONS ==========
echo "[13/20] Installing VSCode extensions..."

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
    "EliotVU.uc"
    "stefan-h-at.source-engine-support"
    "LionDoge.vscript-debug"
    "NilsSoderman.ue-python"
    "mjxcode.vscode-q3shader"
    "shd101wyy.markdown-preview-enhanced"
    "formulahendry.code-runner"
    "donjayamanne.githistory"
    "humao.rest-client"
    "streetsidesoftware.code-spell-checker"
    "Cardinal90.multi-cursor-case-preserve"
    "alefragnani.Bookmarks"
    "WallabyJs.quokka-vscode"
    "ritwickdey.LiveServer"
    "WallabyJs.console-ninja"
    "Monish.regexsnippets"
    "GitHub.copilot"
    "JayBarnes.chatgpt-vscode-plugin"
    "pnp.polacode"
    "Codeium.codeium"
    "oouo-diogo-perdigao.docthis"
    "johnpapa.vscode-peacock"
    "Postman.postman-for-vscode"
)

# Ensure extension and user data directories are correctly set
EXT_DIR="{VOLUME_DIR}/data/extensions"
USER_DATA_DIR="{VOLUME_DIR}/data"
mkdir -p "$EXT_DIR"
chown -R {SERVICE_USER}:{SERVICE_USER} "$USER_DATA_DIR"

for extension in "${{extensions[@]}}"; do
    su - {SERVICE_USER} -c "code-server --install-extension $extension --extensions-dir=$EXT_DIR --user-data-dir=$USER_DATA_DIR"
done


# ========== SYSTEMD ==========
echo "[14/20] Configuring systemd service..."
mkdir -p /etc/systemd/system/code-server@.service.d
cat > /etc/systemd/system/code-server@.service.d/override.conf <<EOF
[Service]
Restart=on-failure
RestartSec=5s
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/{SERVICE_USER}/.pyenv/shims:/home/{SERVICE_USER}/.pyenv/bin"
EOF

systemctl daemon-reexec
systemctl daemon-reload
systemctl enable --now code-server@{SERVICE_USER}

# ========== FIREWALL ==========
echo "[15/20] Configuring firewall..."
ufw allow 22,80,443,{PORT}/tcp
ufw --force enable

# ========== SSL ==========
echo "[16/20] Setting up SSL..."
mkdir -p /etc/letsencrypt
curl -s "{letsencrypt_options_url}" > /etc/letsencrypt/options-ssl-nginx.conf
curl -s "{ssl_dhparams_url}" > /etc/letsencrypt/ssl-dhparams.pem

if [ -f "{DNS_HOOK_SCRIPT}" ]; then
    chmod +x "{DNS_HOOK_SCRIPT}"
    certbot certonly --manual --preferred-challenges=dns \\
        --manual-auth-hook "{DNS_HOOK_SCRIPT} add" \\
        --manual-cleanup-hook "{DNS_HOOK_SCRIPT} clean" \\
        --agree-tos --email "{ADMIN_EMAIL}" \\
        -d "{DOMAIN_NAME}" -d "*.{DOMAIN_NAME}" \\
        --non-interactive --manual-public-ip-logging-ok
else
    echo "No DNS hook found. Using standard Nginx challenge..."
    printf '%s\\ny\\nn\\n' "{ADMIN_EMAIL}" | certbot --nginx -d "{DOMAIN_NAME}" --non-interactive --agree-tos --redirect
fi

# ========== NGINX ==========
echo "[17/20] Configuring Nginx..."
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default
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
ln -sf /etc/nginx/sites-available/vscode /etc/nginx/sites-enabled/
nginx -t && systemctl restart nginx

# ========== RENEWAL ==========
echo "[18/20] Setting certbot auto-renewal..."
CRON_CMD="0 3 * * * /usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx'"
( crontab -l 2>/dev/null | grep -v -F "$CRON_CMD" ; echo "$CRON_CMD" ) | crontab -

# ========== FINALIZE ==========
echo "[19/20] Verifying installation..."
if ! nginx -t; then
    echo "ERROR: Nginx config test failed"; exit 1
fi
if [ ! -f "/etc/letsencrypt/live/{DOMAIN_NAME}/fullchain.pem" ]; then
    echo "ERROR: SSL cert not found!"; exit 1
fi
if ! curl -s -o /dev/null -w "%{{http_code}}" http://localhost:{PORT} | grep -q 200; then
    echo "ERROR: Cannot access code-server on port {PORT}"; exit 1
fi

echo "[20/20] Setup complete! Access: https://{DOMAIN_NAME}:{PORT}"



#Installed Vscode extensions
# https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-azureterraform
# https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-azureappservice
# https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-azurefunctions
# https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-azurestaticwebapps
# https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-azurestorage
# https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-cosmosdb
# https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-docker
# https://marketplace.visualstudio.com/items?itemName=ms-kubernetes-tools.vscode-kubernetes-tools
# https://marketplace.visualstudio.com/items?itemName=netlify.netlify-vscode
# https://marketplace.visualstudio.com/items?itemName=dbaeumer.vscode-eslint
# https://marketplace.visualstudio.com/items?itemName=esbenp.prettier-vscode
# https://marketplace.visualstudio.com/items?itemName=ms-vscode.vscode-typescript-next
# https://marketplace.visualstudio.com/items?itemName=eamodio.gitlens
# https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers
# https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-ssh
# https://marketplace.visualstudio.com/items?itemName=ms-vscode.powershell
# https://marketplace.visualstudio.com/items?itemName=ms-python.python
# https://marketplace.visualstudio.com/items?itemName=ms-toolsai.jupyter
# https://marketplace.visualstudio.com/items?itemName=hashicorp.terraform
# https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml
# https://open-vsx.org/vscode/item?itemName=EliotVU.uc
# https://open-vsx.org/vscode/item?itemName=stefan-h-at.source-engine-support
# https://open-vsx.org/vscode/item?itemName=LionDoge.vscript-debug
# https://open-vsx.org/vscode/item?itemName=NilsSoderman.ue-python
# https://marketplace.visualstudio.com/items?itemName=mjxcode.vscode-q3shader
# https://marketplace.visualstudio.com/items?itemName=shd101wyy.markdown-preview-enhanced
# https://marketplace.visualstudio.com/items?itemName=formulahendry.code-runner
# https://marketplace.visualstudio.com/items?itemName=donjayamanne.githistory
# https://marketplace.visualstudio.com/items?itemName=humao.rest-client
# https://marketplace.visualstudio.com/items?itemName=streetsidesoftware.code-spell-checker
# https://marketplace.visualstudio.com/items?itemName=Cardinal90.multi-cursor-case-preserve
# https://marketplace.visualstudio.com/items?itemName=alefragnani.Bookmarks
# https://marketplace.visualstudio.com/items?itemName=WallabyJs.quokka-vscode
# https://marketplace.visualstudio.com/items?itemName=ritwickdey.LiveServer
# https://marketplace.visualstudio.com/items?itemName=WallabyJs.console-ninja
# https://marketplace.visualstudio.com/items?itemName=Monish.regexsnippets
# https://marketplace.visualstudio.com/items?itemName=GitHub.copilot
# https://marketplace.visualstudio.com/items?itemName=JayBarnes.chatgpt-vscode-plugin
# https://marketplace.visualstudio.com/items?itemName=pnp.polacode
# https://marketplace.visualstudio.com/items?itemName=Codeium.codeium
# https://marketplace.visualstudio.com/items?itemName=oouo-diogo-perdigao.docthis
# https://marketplace.visualstudio.com/items?itemName=johnpapa.vscode-peacock
# https://marketplace.visualstudio.com/items?itemName=Postman.postman-for-vscode
"""
    return script_template

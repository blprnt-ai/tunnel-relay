#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/load_env.sh"

SERVICE_NAME=tunnel-relay
BIN_PATH=/opt/blprnt/tunnel-relay
RUN_USER=blprnt
NGINX_SITE=tunnel-relay
SERVER_NAME=relay.blprnt.ai

SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
NGINX_SITE_PATH="/etc/nginx/sites-available/${NGINX_SITE}"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/${NGINX_SITE}"

ssh $DEPLOY_HOST << ENDSSH
set -euo pipefail
sudo tee "${SERVICE_PATH}" >/dev/null <<EOF
[Unit]
Description=${SERVICE_NAME}
After=network.target

[Service]
User=${RUN_USER}
ExecStart=${BIN_PATH}
Restart=always
RestartSec=2
Environment=TUNNEL_HMAC_KEYS=NoNXOuUI0eueCenbeN+1TQ+jJNrBKjCxDY0my/XaO+k=

[Install]
WantedBy=multi-user.target
EOF

sudo tee "${NGINX_SITE_PATH}" >/dev/null <<EOF
server {
  listen 80;
  server_name ${SERVER_NAME};

  location / {
    proxy_pass http://127.0.0.1:7187;
    proxy_http_version 1.1;
    proxy_set_header Host \\\$host;
    proxy_set_header X-Real-IP \\\$remote_addr;
    proxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \\\$scheme;
  }
}
EOF

if [ ! -L "${NGINX_SITE_LINK}" ]; then
  sudo ln -s "${NGINX_SITE_PATH}" "${NGINX_SITE_LINK}"
fi

sudo systemctl daemon-reload
sudo systemctl enable "${SERVICE_NAME}"
sudo systemctl restart "${SERVICE_NAME}"
sudo nginx -t
sudo systemctl restart nginx
ENDSSH
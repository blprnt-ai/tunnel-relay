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
Environment=SLACK_CLIENT_ID=1596789697126.10418569425428
Environment=SLACK_CLIENT_SECRET=1ab4411e1740a6fea9ea5ed739dc9eee
Environment=SLACK_SIGNING_SECRET=b9a17a0acaba45754bb0f8e9c2bfcfdb
Environment=SLACK_SCOPES=chat:write,im:write

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable "${SERVICE_NAME}"
sudo systemctl restart "${SERVICE_NAME}"
ENDSSH
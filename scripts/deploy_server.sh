#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/load_env.sh"

REMOTE_DIR=/opt/blprnt/tunnel-relay-build
SERVICE_NAME=tunnel-relay
BIN_PATH=/opt/blprnt/tunnel-relay

RSYNC_EXCLUDES=(--exclude .git --exclude target)

rsync -az --delete "${RSYNC_EXCLUDES[@]}" ./ "${DEPLOY_HOST}:${REMOTE_DIR}"

ssh $DEPLOY_HOST << ENDSSH
  set -euo pipefail
  cd '${REMOTE_DIR}'
  cargo build -p tunnel-server --release
  sudo install -m 0755 'target/release/tunnel-server' '${BIN_PATH}'
  sudo systemctl restart '${SERVICE_NAME}'
  journalctl -u '${SERVICE_NAME}' -f
ENDSSH
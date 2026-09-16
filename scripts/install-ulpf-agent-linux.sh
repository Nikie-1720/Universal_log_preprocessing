#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/ulpf-agent"
DATA_DIR="/var/lib/ulpf-agent"
SERVICE_NAME="ulpf-agent"
GATEWAY="${ULPF_GATEWAY:-http://127.0.0.1:5173}"

log(){ echo "[ULPF] $*"; }

log "Detecting operating system..."
OS_NAME="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-Linux}" || uname -s)"
ARCH="$(uname -m)"
echo "  OS           : ${OS_NAME}"
echo "  Architecture : ${ARCH}"
echo "  Hostname     : $(hostname)"

PYTHON_BIN=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,9) else 1)' >/dev/null 2>&1; then
      PYTHON_BIN="$(command -v "$candidate")"
      break
    fi
  fi
done
[[ -n "$PYTHON_BIN" ]] || { echo "Python 3.9+ is required for source installation." >&2; exit 1; }

log "Installing ULPF Agent..."
sudo mkdir -p "$INSTALL_DIR" "$DATA_DIR/state"
sudo cp -r agent "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/agent/agent.py"

CONFIG_PATH="$DATA_DIR/agent.yaml"
STATE_DIR="$DATA_DIR/state"

sudo tee "$CONFIG_PATH" >/dev/null <<EOF_CFG
gateway: "$GATEWAY"
token: "Tnikita1800"
name: ""
agent_id_file: "$STATE_DIR/agent-id"
spool: "$STATE_DIR/spool.db"
offset_file: "$STATE_DIR/offsets.json"
files:
  - /var/log/syslog
  - /var/log/messages
  - /var/log/auth.log
  - /var/log/secure
  - /var/log/audit/audit.log
directories: []
journald: true
windows_eventlog: false
poll_interval: 2
windows_poll_interval: 5
send_interval: 0.5
batch_size: 100
heartbeat_interval: 10
EOF_CFG

sudo tee "/etc/systemd/system/${SERVICE_NAME}.service" >/dev/null <<EOF_SERVICE
[Unit]
Description=ULPF Collector Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}/agent
ExecStart=${PYTHON_BIN} ${INSTALL_DIR}/agent/agent.py --config ${CONFIG_PATH}
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=false
ReadWritePaths=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF_SERVICE

sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl restart "$SERVICE_NAME"

log "ULPF Agent installed and started."
echo "  Install : $INSTALL_DIR"
echo "  Data    : $DATA_DIR"
echo "  Config  : $CONFIG_PATH"
echo "  Service : $SERVICE_NAME"

cat > /tmp/install-ncpa-source.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# === Einstellungen (kannst du auch per ENV überschreiben) ===
NCPA_DIR="${NCPA_DIR:-/opt/ncpa-src}"
VENV_DIR="${VENV_DIR:-/opt/ncpa-venv}"
TOKEN="${NCPA_TOKEN:-}"
ALLOWED_HOSTS="${NCPA_ALLOWED_HOSTS:-127.0.0.1,192.168.1.0/24}"
PORT="${NCPA_PORT:-5693}"

if [[ -z "$TOKEN" ]]; then
  echo "ERROR: Bitte Token setzen, z.B.: NCPA_TOKEN='supersecret' $0"
  exit 1
fi

echo "[1/7] Pakete installieren..."
sudo apt-get update
sudo apt-get install -y \
  git curl ca-certificates \
  python3 python3-venv python3-pip \
  build-essential python3-dev libffi-dev libssl-dev

echo "[2/7] Source holen/aktualisieren..."
if [[ -d "$NCPA_DIR/.git" ]]; then
  sudo git -C "$NCPA_DIR" pull --ff-only
else
  sudo rm -rf "$NCPA_DIR"
  sudo git clone --depth 1 https://github.com/NagiosEnterprises/ncpa.git "$NCPA_DIR"
fi

echo "[3/7] venv anlegen..."
sudo rm -rf "$VENV_DIR"
sudo python3 -m venv "$VENV_DIR"
sudo "$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel

echo "[4/7] Python Dependencies installieren..."
# Minimal + bewährt für Listener in deinem Layout
sudo "$VENV_DIR/bin/pip" install \
  flask flask-login flask-wtf werkzeug \
  cryptography psutil requests pyopenssl waitress \
  gevent gevent-websocket

echo "[5/7] Config schreiben (Token/Allowed Hosts/uid/gid)..."
CFG="$NCPA_DIR/agent/etc/ncpa.cfg"
SAMPLE="$NCPA_DIR/agent/etc/ncpa.cfg.sample"

if [[ ! -f "$SAMPLE" ]]; then
  echo "ERROR: Sample Config nicht gefunden: $SAMPLE"
  exit 1
fi

sudo cp -f "$SAMPLE" "$CFG"

# Token
sudo sed -i "s/^community_string\s*=.*/community_string = ${TOKEN}/" "$CFG"
# Allowed Hosts
sudo sed -i "s|^allowed_hosts\s*=.*|allowed_hosts = ${ALLOWED_HOSTS}|" "$CFG"
# uid/gid: läuft als root (damit setuid/setgid nicht scheitert)
sudo sed -i "s/^uid\s*=.*/uid = root/" "$CFG"
sudo sed -i "s/^gid\s*=.*/gid = root/" "$CFG"
# Port (falls in Config vorhanden; wenn nicht, ignoriert sed es je nach sample)
sudo sed -i "s/^port\s*=.*/port = ${PORT}/" "$CFG" || true

echo "[6/7] systemd Service installieren..."
sudo tee /etc/systemd/system/ncpa_listener.service >/dev/null <<SERVICE
[Unit]
Description=NCPA Listener (source)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$NCPA_DIR/agent
Environment=PYTHONPATH=$NCPA_DIR/agent
ExecStart=$VENV_DIR/bin/python $NCPA_DIR/agent/ncpa.py -l -c $CFG
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable --now ncpa_listener

echo "[7/7] Test API..."
sleep 1
curl -sk "https://127.0.0.1:${PORT}/api/system?token=${TOKEN}" | head -c 200 && echo
echo "OK: NCPA Listener läuft. URL: https://$(hostname -I | awk '{print $1}'):${PORT}/"
EOF

chmod +x /tmp/install-ncpa-source.sh

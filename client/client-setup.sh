sudo tee /tmp/install-ncpa-source.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# --- Defaults (per ENV überschreibbar) ---
NCPA_DIR="${NCPA_DIR:-/opt/ncpa-src}"
VENV_DIR="${VENV_DIR:-/opt/ncpa-venv}"
TOKEN="${NCPA_TOKEN:-}"
PORT="${NCPA_PORT:-5693}"

# LAN / Monitoring-Netze (Default: dein LAN)
LAN_CIDR="${NCPA_LAN_CIDR:-192.168.1.0/24}"

# Zusätzliche erlaubte Hosts/Netze (kommagetrennt), optional
EXTRA_ALLOWED="${NCPA_EXTRA_ALLOWED_HOSTS:-}"

# --- Validate ---
if [[ -z "${TOKEN}" ]]; then
  echo "ERROR: Bitte Token setzen, z.B.: sudo NCPA_TOKEN='secret' bash $0"
  exit 1
fi

echo "[1/8] Pakete installieren..."
apt-get update
apt-get install -y \
  git curl ca-certificates \
  python3 python3-venv python3-pip \
  build-essential python3-dev libffi-dev libssl-dev \
  openssl >/dev/null

echo "[2/8] Source holen/aktualisieren..."
if [[ -d "${NCPA_DIR}/.git" ]]; then
  git -C "${NCPA_DIR}" pull --ff-only
else
  rm -rf "${NCPA_DIR}"
  git clone --depth 1 https://github.com/NagiosEnterprises/ncpa.git "${NCPA_DIR}"
fi

echo "[3/8] venv anlegen..."
rm -rf "${VENV_DIR}"
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --upgrade pip setuptools wheel >/dev/null

echo "[4/8] Python Dependencies installieren..."
"${VENV_DIR}/bin/pip" install >/dev/null \
  flask flask-login flask-wtf werkzeug \
  cryptography psutil requests pyopenssl waitress \
  gevent gevent-websocket

echo "[5/8] allowed_hosts automatisch bauen (LAN + Docker-Netze)..."
ALLOWED_HOSTS="127.0.0.1,${LAN_CIDR}"

# Docker-Subnetze adden, wenn Docker verfügbar ist
if command -v docker >/dev/null 2>&1; then
  # alle user-defined networks + bridge
  while read -r net; do
    subnet="$(docker network inspect "$net" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null || true)"
    if [[ -n "${subnet}" && "${subnet}" != "<no value>" ]]; then
      ALLOWED_HOSTS="${ALLOWED_HOSTS},${subnet}"
    fi
  done < <(docker network ls --format '{{.Name}}' 2>/dev/null | sort -u)
fi

# Extra allowed
if [[ -n "${EXTRA_ALLOWED}" ]]; then
  ALLOWED_HOSTS="${ALLOWED_HOSTS},${EXTRA_ALLOWED}"
fi

# Duplikate grob raus (Best-effort)
ALLOWED_HOSTS="$(echo "${ALLOWED_HOSTS}" | tr ',' '\n' | awk 'NF{a[$0]=1} END{for(k in a) print k}' | sort | paste -sd, -)"

echo "allowed_hosts -> ${ALLOWED_HOSTS}"

echo "[6/8] Config schreiben + SSL aktivieren..."
CFG="${NCPA_DIR}/agent/etc/ncpa.cfg"
SAMPLE="${NCPA_DIR}/agent/etc/ncpa.cfg.sample"
cp -f "${SAMPLE}" "${CFG}"

# helper: set or uncomment+set key = value (case-insensitive)
set_kv() {
  local key="$1" val="$2" file="$3"
  if grep -qiE "^[#;]?\s*${key}\s*=" "$file"; then
    sed -i -E "s|^[#;]?\s*${key}\s*=.*|${key} = ${val}|I" "$file"
  else
    printf "\n%s = %s\n" "$key" "$val" >> "$file"
  fi
}

set_kv "community_string" "${TOKEN}" "${CFG}"
set_kv "allowed_hosts" "${ALLOWED_HOSTS}" "${CFG}"

# bind/port
set_kv "ip" "0.0.0.0" "${CFG}"
set_kv "port" "${PORT}" "${CFG}"

# SSL Settings (wichtig!)
set_kv "use_ssl" "1" "${CFG}"
set_kv "certificate" "adhoc" "${CFG}"
set_kv "ssl_version" "TLSv1_2" "${CFG}"

echo "[7/8] systemd Service installieren (Foreground, Listener-only)..."
cat >/etc/systemd/system/ncpa_listener.service <<SERVICE
[Unit]
Description=NCPA Listener (source)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${NCPA_DIR}/agent
Environment=PYTHONPATH=${NCPA_DIR}/agent
ExecStart=${VENV_DIR}/bin/python ${NCPA_DIR}/agent/ncpa.py -n -l -c ${CFG}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now ncpa_listener

echo "[8/8] Quick test (local HTTPS)..."
sleep 1
curl -sk "https://127.0.0.1:${PORT}/api/system?token=${TOKEN}" | head -c 220 && echo
echo "OK: NCPA Listener läuft (HTTPS) auf Port ${PORT}"
EOF

sudo chmod +x /tmp/install-ncpa-source.sh

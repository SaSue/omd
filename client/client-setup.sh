#!/usr/bin/env bash
set -euo pipefail

############################################
# Konfiguration (per ENV überschreibbar)
############################################
NCPA_DIR="${NCPA_DIR:-/opt/ncpa-src}"
VENV_DIR="${VENV_DIR:-/opt/ncpa-venv}"
PORT="${NCPA_PORT:-5693}"

# MUSS gesetzt werden
TOKEN="${NCPA_TOKEN:-}"

# Lokales LAN
LAN_CIDR="${NCPA_LAN_CIDR:-192.168.1.0/24}"

# optionale zusätzliche Netze
EXTRA_ALLOWED="${NCPA_EXTRA_ALLOWED_HOSTS:-}"

# NCPA Source
NCPA_GIT_URL="https://github.com/NagiosEnterprises/ncpa.git"

############################################
# Checks
############################################
if [[ -z "${TOKEN}" ]]; then
  echo "ERROR: NCPA_TOKEN nicht gesetzt"
  echo "Beispiel:"
  echo "sudo NCPA_TOKEN=\"<TOKEN>\" bash $0"
  exit 1
fi

############################################
echo "[1/9] System vorbereiten"
############################################
sudo apt update
sudo apt install -y \
  git curl ca-certificates \
  python3 python3-venv python3-pip \
  build-essential python3-dev libffi-dev libssl-dev \
  openssl \
  nagios-plugins-contrib

############################################
echo "[2/9] NCPA Source holen / aktualisieren"
############################################
if [[ -d "${NCPA_DIR}/.git" ]]; then
  sudo git -C "${NCPA_DIR}" pull --ff-only
else
  sudo rm -rf "${NCPA_DIR}"
  sudo git clone --depth 1 "${NCPA_GIT_URL}" "${NCPA_DIR}"
fi

############################################
echo "[3/9] Python venv erstellen"
############################################
sudo rm -rf "${VENV_DIR}"
sudo python3 -m venv "${VENV_DIR}"
sudo "${VENV_DIR}/bin/pip" install --upgrade pip setuptools wheel

sudo "${VENV_DIR}/bin/pip" install \
  flask flask-login flask-wtf werkzeug \
  cryptography psutil requests pyopenssl waitress \
  gevent gevent-websocket

############################################
echo "[4/9] allowed_hosts automatisch ermitteln"
############################################
ALLOWED_HOSTS="127.0.0.1,${LAN_CIDR}"

if command -v docker >/dev/null 2>&1; then
  while read -r net; do
    subnet="$(docker network inspect "$net" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null || true)"
    if [[ -n "${subnet}" && "${subnet}" != "<no value>" ]]; then
      ALLOWED_HOSTS="${ALLOWED_HOSTS},${subnet}"
    fi
  done < <(docker network ls --format '{{.Name}}')
fi

if [[ -n "${EXTRA_ALLOWED}" ]]; then
  ALLOWED_HOSTS="${ALLOWED_HOSTS},${EXTRA_ALLOWED}"
fi

# Duplikate entfernen
ALLOWED_HOSTS="$(echo "${ALLOWED_HOSTS}" | tr ',' '\n' | awk 'NF{a[$0]=1} END{for(k in a) print k}' | sort | paste -sd, -)"
echo "allowed_hosts = ${ALLOWED_HOSTS}"

############################################
echo "[5/9] NCPA Config schreiben (SSL + Token)"
############################################
CFG="${NCPA_DIR}/agent/etc/ncpa.cfg"
SAMPLE="${NCPA_DIR}/agent/etc/ncpa.cfg.sample"
sudo cp -f "${SAMPLE}" "${CFG}"

set_kv () {
  local k="$1" v="$2"
  sudo sed -i -E "s|^[#;]?\s*${k}\s*=.*|${k} = ${v}|I" "${CFG}" || true
  if ! grep -qiE "^${k}\s*=" "${CFG}"; then
    echo "${k} = ${v}" | sudo tee -a "${CFG}" >/dev/null
  fi
}

set_kv community_string "${TOKEN}"
set_kv allowed_hosts "${ALLOWED_HOSTS}"
set_kv ip "0.0.0.0"
set_kv port "${PORT}"

# SSL
set_kv use_ssl "1"
set_kv certificate "adhoc"
set_kv ssl_version "TLSv1_2"

############################################
echo "[6/9] check_apt für NCPA verfügbar machen"
############################################
NCPA_PLUGDIR="${NCPA_DIR}/agent/plugins"
sudo mkdir -p "${NCPA_PLUGDIR}"

if [[ -x /usr/lib/nagios/plugins/check_apt ]]; then
  sudo ln -sf /usr/lib/nagios/plugins/check_apt "${NCPA_PLUGDIR}/check_apt"
  sudo chmod +x "${NCPA_PLUGDIR}/check_apt"
fi

# Security-Wrapper
sudo tee "${NCPA_PLUGDIR}/check_apt_security" >/dev/null <<'EOF'
#!/bin/bash
/usr/lib/nagios/plugins/check_apt --only-security
EOF
sudo chmod +x "${NCPA_PLUGDIR}/check_apt_security"

############################################
echo "[7/9] systemd Service (-n + -l)"
############################################
sudo tee /etc/systemd/system/ncpa_listener.service >/dev/null <<SERVICE
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

sudo systemctl daemon-reload
sudo systemctl enable --now ncpa_listener

############################################
echo "[8/9] NCPA Neustart"
############################################
sudo systemctl restart ncpa_listener
sleep 1

############################################
echo "[9/9] Lokaler Test"
############################################
curl -sk "https://127.0.0.1:${PORT}/api/system?token=${TOKEN}" | head -c 200 && echo
curl -sk "https://127.0.0.1:${PORT}/api/plugins/check_apt?token=${TOKEN}" || true

echo "========================================="
echo "FERTIG ✅  NCPA läuft auf Port ${PORT}"
echo "APT Updates & Security Updates verfügbar"
echo "========================================="

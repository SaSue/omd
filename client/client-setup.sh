#!/usr/bin/env bash
set -euo pipefail

# -------------------------
# Config via ENV (empfohlen)
# -------------------------
: "${NCPA_TOKEN:?Set NCPA_TOKEN env var}"
: "${NCPA_ALLOWED_HOSTS:=127.0.0.1,192.168.1.0/24}"
: "${NCPA_PORT:=5693}"
: "${NCPA_USE_SSL:=1}"                 # 1 = HTTPS, 0 = HTTP
: "${NCPA_CERTIFICATE:=adhoc}"         # adhoc ok für intranet
: "${NCPA_SSL_VERSION:=TLSv1_2}"
: "${NCPA_BIND_IP:=0.0.0.0}"

# Optional: zusätzliche Netze (z.B. Docker bridge / proxy-net)
# Beispiel: export NCPA_EXTRA_ALLOWED="172.17.0.0/16,10.0.5.0/24"
: "${NCPA_EXTRA_ALLOWED:=}"

# Paths (Source-Layout)
NCPA_SRC="/opt/ncpa-src"
NCPA_AGENT="${NCPA_SRC}/agent"
NCPA_CFG="${NCPA_AGENT}/etc/ncpa.cfg"
NCPA_PLUGINS="${NCPA_AGENT}/plugins"
NCPA_VENV="/opt/ncpa-venv"

SERVICE_FILE="/etc/systemd/system/ncpa_listener.service"

# -------------------------
# Helper
# -------------------------
append_allowed_hosts() {
  local base="$1"
  local extra="$2"
  if [[ -n "$extra" ]]; then
    echo "${base},${extra}"
  else
    echo "${base}"
  fi
}

ALLOWED_HOSTS="$(append_allowed_hosts "$NCPA_ALLOWED_HOSTS" "$NCPA_EXTRA_ALLOWED")"

echo "[*] Installing prerequisites ..."
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
  ca-certificates curl jq python3 python3-venv python3-pip \
  nagios-plugins-contrib

echo "[*] Ensure plugin directory exists: ${NCPA_PLUGINS}"
sudo install -d -m 0755 "${NCPA_PLUGINS}"

# -------------------------
# (A) Deploy Docker plugins (only if docker exists)
# -------------------------
if command -v docker >/dev/null 2>&1; then
  echo "[*] Docker detected -> installing NCPA docker plugins"

  # 1) Restart-policy containers check
  sudo tee "${NCPA_PLUGINS}/check_docker_restart_policy" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

bad_unhealthy=()
bad_exited=()
bad_restarting=()
total=0
running=0

command -v docker >/dev/null 2>&1 || { echo "UNKNOWN - docker not found"; exit 3; }

mapfile -t ids < <(docker ps -a --format '{{.ID}}')

for id in "${ids[@]}"; do
  restart="$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$id" 2>/dev/null || echo no)"
  [[ "$restart" == "no" || -z "$restart" ]] && continue

  total=$((total+1))
  name="$(docker inspect --format '{{.Name}}' "$id" | sed 's|/||')"
  state="$(docker inspect --format '{{.State.Status}}' "$id")"
  health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id")"

  case "$state" in
    running)
      running=$((running+1))
      [[ "$health" == "unhealthy" ]] && bad_unhealthy+=("$name")
      ;;
    exited|dead)
      bad_exited+=("$name")
      ;;
    restarting)
      bad_restarting+=("$name")
      ;;
  esac
done

msg="restart-policy containers: running ${running}/${total}"
perf="total=${total} running=${running} unhealthy=${#bad_unhealthy[@]} exited=${#bad_exited[@]} restarting=${#bad_restarting[@]}"

if (( ${#bad_unhealthy[@]} > 0 )); then
  echo "CRITICAL - ${msg}; unhealthy: ${bad_unhealthy[*]} | ${perf}"
  exit 2
fi
if (( ${#bad_exited[@]} > 0 )); then
  echo "CRITICAL - ${msg}; exited: ${bad_exited[*]} | ${perf}"
  exit 2
fi
if (( ${#bad_restarting[@]} > 0 )); then
  echo "WARNING - ${msg}; restarting: ${bad_restarting[*]} | ${perf}"
  exit 1
fi

echo "OK - ${msg} | ${perf}"
exit 0
EOF

  # 2) Swarm services check (OK if no swarm services)
  sudo tee "${NCPA_PLUGINS}/check_docker_swarm_services" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

command -v docker >/dev/null 2>&1 || { echo "UNKNOWN - docker not found"; exit 3; }

mapfile -t services < <(docker service ls --format '{{.ID}}|{{.Name}}|{{.Replicas}}' 2>/dev/null || true)
if [[ ${#services[@]} -eq 0 ]]; then
  echo "OK - no swarm services"
  exit 0
fi

degraded=()
total=0

for s in "${services[@]}"; do
  id="${s%%|*}"
  rest="${s#*|}"
  name="${rest%%|*}"
  repl="${rest##*|}"

  running="${repl%%/*}"
  desired="${repl##*/}"
  total=$((total+1))

  if [[ "$running" != "$desired" ]]; then
    degraded+=("${name}(${running}/${desired})")
    continue
  fi

  if docker service ps "$id" --no-trunc --format '{{.CurrentState}} {{.Error}}' \
      | grep -E '(Failed|Rejected)' >/dev/null; then
    degraded+=("${name}(task-failure)")
  fi
done

if (( ${#degraded[@]} > 0 )); then
  echo "CRITICAL - swarm services degraded: ${degraded[*]}"
  exit 2
fi

echo "OK - swarm services healthy (${total})"
exit 0
EOF

  sudo chmod 0755 \
    "${NCPA_PLUGINS}/check_docker_restart_policy" \
    "${NCPA_PLUGINS}/check_docker_swarm_services"

else
  echo "[*] Docker not found -> skipping docker plugins"
fi

# -------------------------
# (B) Ensure ncpa.cfg has the right values (ssl + allowed_hosts + bind)
# -------------------------
if [[ ! -f "${NCPA_CFG}" ]]; then
  echo "[!] ${NCPA_CFG} not found. I assume you already staged NCPA source to ${NCPA_SRC}."
  echo "    Please ensure NCPA source exists at ${NCPA_AGENT} and ncpa.cfg exists."
  exit 1
fi

echo "[*] Updating NCPA config: ${NCPA_CFG}"
sudo sed -i -E "s|^#?\s*community_string\s*=.*|community_string = ${NCPA_TOKEN}|g" "${NCPA_CFG}" || true
sudo sed -i -E "s|^#?\s*allowed_hosts\s*=.*|allowed_hosts = ${ALLOWED_HOSTS}|g" "${NCPA_CFG}" || true
sudo sed -i -E "s|^#?\s*ip\s*=.*|ip = ${NCPA_BIND_IP}|g" "${NCPA_CFG}" || true
sudo sed -i -E "s|^#?\s*port\s*=.*|port = ${NCPA_PORT}|g" "${NCPA_CFG}" || true
sudo sed -i -E "s|^#?\s*use_ssl\s*=.*|use_ssl = ${NCPA_USE_SSL}|g" "${NCPA_CFG}" || true
sudo sed -i -E "s|^#?\s*certificate\s*=.*|certificate = ${NCPA_CERTIFICATE}|g" "${NCPA_CFG}" || true
sudo sed -i -E "s|^#?\s*ssl_version\s*=.*|ssl_version = ${NCPA_SSL_VERSION}|g" "${NCPA_CFG}" || true

# -------------------------
# (C) Ensure systemd service uses -n -l and correct PYTHONPATH
# -------------------------
echo "[*] Ensuring systemd unit: ${SERVICE_FILE}"
if [[ ! -f "${SERVICE_FILE}" ]]; then
  echo "[!] ${SERVICE_FILE} not found. Creating it."
  sudo tee "${SERVICE_FILE}" >/dev/null <<EOF
[Unit]
Description=NCPA Listener (source)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${NCPA_AGENT}
Environment=PYTHONPATH=${NCPA_AGENT}
ExecStart=${NCPA_VENV}/bin/python ${NCPA_AGENT}/ncpa.py -n -l -c ${NCPA_CFG}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
else
  # patch ExecStart line (idempotent)
  sudo sed -i -E "s|^ExecStart=.*|ExecStart=${NCPA_VENV}/bin/python ${NCPA_AGENT}/ncpa.py -n -l -c ${NCPA_CFG}|g" "${SERVICE_FILE}"
  sudo sed -i -E "s|^Environment=PYTHONPATH=.*|Environment=PYTHONPATH=${NCPA_AGENT}|g" "${SERVICE_FILE}"
  sudo sed -i -E "s|^WorkingDirectory=.*|WorkingDirectory=${NCPA_AGENT}|g" "${SERVICE_FILE}"
fi

sudo systemctl daemon-reload
sudo systemctl enable --now ncpa_listener
sudo systemctl restart ncpa_listener

echo "[*] Verifying plugins visible via API ..."
if [[ "${NCPA_USE_SSL}" == "1" ]]; then
  curl -sk "https://127.0.0.1:${NCPA_PORT}/api/plugins?token=${NCPA_TOKEN}" | head -c 1200 || true
else
  curl -s "http://127.0.0.1:${NCPA_PORT}/api/plugins?token=${NCPA_TOKEN}" | head -c 1200 || true
fi

echo "[OK] Rollout finished.
- allowed_hosts=${ALLOWED_HOSTS}
- use_ssl=${NCPA_USE_SSL} port=${NCPA_PORT}
- docker plugins: $(command -v docker >/dev/null 2>&1 && echo installed || echo skipped)
"

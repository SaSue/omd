#!/usr/bin/env bash
set -euo pipefail

# -------------------------
# Required ENV
# -------------------------
: "${NCPA_TOKEN:?Set NCPA_TOKEN env var}"
: "${NCPA_ALLOWED_HOSTS:?Set NCPA_ALLOWED_HOSTS env var}"

# -------------------------
# Optional ENV defaults
# -------------------------
: "${NCPA_PORT:=5693}"
: "${NCPA_BIND_IP:=0.0.0.0}"
: "${NCPA_USE_SSL:=1}"                 # 1=https, 0=http
: "${NCPA_CERTIFICATE:=adhoc}"         # adhoc ok
: "${NCPA_SSL_VERSION:=TLSv1_2}"
: "${NCPA_EXTRA_ALLOWED:=}"            # e.g. "172.17.0.0/16,10.0.5.0/24"
: "${NCPA_REF:=}"                      # e.g. "v3.2.2" or commit; empty = default branch

# Layout (wie bei dir)
NCPA_SRC="/opt/ncpa-src"
NCPA_AGENT="${NCPA_SRC}/agent"
NCPA_CFG="${NCPA_AGENT}/etc/ncpa.cfg"
NCPA_PLUGINS="${NCPA_AGENT}/plugins"
NCPA_VENV="/opt/ncpa-venv"

SERVICE_FILE="/etc/systemd/system/ncpa_listener.service"
SERVICE_NAME="ncpa_listener"

ALLOWED_HOSTS="${NCPA_ALLOWED_HOSTS}"
if [[ -n "${NCPA_EXTRA_ALLOWED}" ]]; then
  ALLOWED_HOSTS="${ALLOWED_HOSTS},${NCPA_EXTRA_ALLOWED}"
fi

echo "[*] Installing prerequisites (apt)..."
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
  ca-certificates curl jq git \
  python3 python3-venv python3-pip \
  nagios-plugins-contrib nagios-plugins

echo "[*] Ensuring NCPA source exists at ${NCPA_SRC} ..."
if [[ ! -d "${NCPA_SRC}/.git" ]]; then
  sudo mkdir -p "${NCPA_SRC}"
  sudo chown -R root:root "${NCPA_SRC}"
  # Clone as root, keep permissions predictable
  sudo git clone https://github.com/NagiosEnterprises/ncpa.git "${NCPA_SRC}"
else
  echo "    Source already present, pulling updates..."
  sudo git -C "${NCPA_SRC}" fetch --all --tags
fi

if [[ -n "${NCPA_REF}" ]]; then
  echo "[*] Checking out ref: ${NCPA_REF}"
  sudo git -C "${NCPA_SRC}" checkout -f "${NCPA_REF}"
else
  echo "[*] Using default branch (no NCPA_REF provided)"
  sudo git -C "${NCPA_SRC}" checkout -f "$(sudo git -C "${NCPA_SRC}" symbolic-ref --short HEAD)"
fi

if [[ ! -d "${NCPA_AGENT}" ]]; then
  echo "[!] Expected agent dir not found: ${NCPA_AGENT}"
  echo "    Repo layout unexpected. Aborting."
  exit 1
fi

echo "[*] Creating venv at ${NCPA_VENV} ..."
if [[ ! -x "${NCPA_VENV}/bin/python" ]]; then
  sudo python3 -m venv "${NCPA_VENV}"
fi

echo "[*] Installing python runtime deps into venv ..."
# NCPA source install ohne wheel build: wir installieren Runtime deps direkt.
sudo "${NCPA_VENV}/bin/pip" install -U pip setuptools wheel >/dev/null

# Runtime deps, die du in der Praxis gebraucht hast (flask, geventwebsocket etc.)
sudo "${NCPA_VENV}/bin/pip" install -U \
  flask requests psutil \
  gevent gevent-websocket geventhttpclient \
  cryptography pyopenssl \
  jinja2 werkzeug itsdangerous click >/dev/null

echo "[*] Ensuring ncpa.cfg exists ..."
if [[ ! -f "${NCPA_CFG}" ]]; then
  # fallback: some repos keep example config
  if [[ -f "${NCPA_AGENT}/etc/ncpa.cfg.example" ]]; then
    sudo cp -a "${NCPA_AGENT}/etc/ncpa.cfg.example" "${NCPA_CFG}"
  else
    echo "[!] ncpa.cfg not found at ${NCPA_CFG}"
    exit 1
  fi
fi

echo "[*] Configuring ncpa.cfg (token, allowed_hosts, ssl, bind, port) ..."
# Set/replace keys (uncomment if needed)
sudo sed -i -E "s|^#?\s*community_string\s*=.*|community_string = ${NCPA_TOKEN}|g" "${NCPA_CFG}" || true
sudo sed -i -E "s|^#?\s*allowed_hosts\s*=.*|allowed_hosts = ${ALLOWED_HOSTS}|g" "${NCPA_CFG}" || true
sudo sed -i -E "s|^#?\s*ip\s*=.*|ip = ${NCPA_BIND_IP}|g" "${NCPA_CFG}" || true
sudo sed -i -E "s|^#?\s*port\s*=.*|port = ${NCPA_PORT}|g" "${NCPA_CFG}" || true
sudo sed -i -E "s|^#?\s*use_ssl\s*=.*|use_ssl = ${NCPA_USE_SSL}|g" "${NCPA_CFG}" || true
sudo sed -i -E "s|^#?\s*certificate\s*=.*|certificate = ${NCPA_CERTIFICATE}|g" "${NCPA_CFG}" || true
sudo sed -i -E "s|^#?\s*ssl_version\s*=.*|ssl_version = ${NCPA_SSL_VERSION}|g" "${NCPA_CFG}" || true
# ensure uid/gid exist (default "nagios" breaks on fresh clients)
sudo sed -i -E \
  -e 's|^#?\s*uid\s*=.*|uid = root|' \
  -e 's|^#?\s*gid\s*=.*|gid = root|' \
  "${NCPA_CFG}" 

echo "[*] Installing APT Check plugin into ${NCPA_PLUGINS} ..."
sudo ln -sf /usr/lib/nagios/plugins/check_apt /opt/ncpa-src/agent/plugins/check_apt
sudo chmod +x /opt/ncpa-src/agent/plugins/check_apt

echo "[*] Installing docker plugins into ${NCPA_PLUGINS} ..."
sudo install -d -m 0755 "${NCPA_PLUGINS}"

# --- check_docker_restart_policy ---
sudo tee "${NCPA_PLUGINS}/check_docker_restart_policy" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

command -v docker >/dev/null 2>&1 || { echo "UNKNOWN - docker not found"; exit 3; }

bad_unhealthy=()
bad_exited=()
bad_restarting=()
total=0
running=0

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

# --- check_docker_swarm_services (fixed: no history false positives) ---
sudo tee "${NCPA_PLUGINS}/check_docker_swarm_services" >/dev/null <<'EOF'
sudo tee /opt/ncpa-src/agent/plugins/check_docker_swarm_services >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

command -v docker >/dev/null 2>&1 || { echo "UNKNOWN - docker not found"; exit 3; }

# Optional: zusätzlich per ENV ignorieren (Regex auf Service-Name)
# Beispiel: export MONITORING_IGNORE_REGEX='^(certbot|backup|job-.*)$'
IGNORE_REGEX="${MONITORING_IGNORE_REGEX:-}"

mapfile -t services < <(docker service ls --format '{{.ID}}|{{.Name}}|{{.Replicas}}' 2>/dev/null || true)
if [[ ${#services[@]} -eq 0 ]]; then
  echo "OK - no swarm services"
  exit 0
fi

degraded=()
total=0
checked=0
ignored=0

for s in "${services[@]}"; do
  id="${s%%|*}"
  rest="${s#*|}"
  name="${rest%%|*}"
  repl="${rest##*|}"

  # 1) Ignore by label monitoring.ignore=true
  ign="$(docker service inspect "$id" --format '{{ index .Spec.Labels "monitoring.ignore" }}' 2>/dev/null || true)"
  if [[ "$ign" == "true" || "$ign" == "1" || "$ign" == "yes" ]]; then
    ignored=$((ignored+1))
    continue
  fi

  # 2) Optional ignore by regex on service name
  if [[ -n "$IGNORE_REGEX" ]] && echo "$name" | grep -Eq "$IGNORE_REGEX"; then
    ignored=$((ignored+1))
    continue
  fi

  checked=$((checked+1))
  total=$((total+1))

  running="${repl%%/*}"
  desired="${repl##*/}"

  # Replicas mismatch => kritisch (gilt für replicated services)
  if [[ "$running" != "$desired" ]]; then
    degraded+=("${name}(${running}/${desired})")
    continue
  fi

  # Task-Failures: nur CURRENT desired-state=running (History ignorieren)
  out="$(docker service ps "$id" --no-trunc --filter desired-state=running \
          --format '{{.CurrentState}} {{.Error}}' 2>/dev/null || true)"

  if [[ -n "$out" ]]; then
    if echo "$out" | grep -E '(Failed|Rejected)' >/dev/null; then
      degraded+=("${name}(task-failure)")
      continue
    fi
    # Alles, was noch nicht Running ist, als "degraded" melden (Rollout/Startphase)
    if echo "$out" | grep -v '^Running ' >/dev/null; then
      degraded+=("${name}(not-running-yet)")
      continue
    fi
  fi
done

# Wenn ALLE Services ignoriert werden => OK
if (( checked == 0 )); then
  echo "OK - all swarm services ignored (${ignored})"
  exit 0
fi

if (( ${#degraded[@]} > 0 )); then
  echo "CRITICAL - swarm services degraded: ${degraded[*]} (checked=${checked}, ignored=${ignored})"
  exit 2
fi

echo "OK - swarm services healthy (checked=${checked}, ignored=${ignored})"
exit 0
EOF

sudo chmod 0755 \
  "${NCPA_PLUGINS}/check_docker_restart_policy" \
  "${NCPA_PLUGINS}/check_docker_swarm_services"

echo "[*] Creating/patching systemd unit ${SERVICE_FILE} ..."
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

echo "[*] Starting/restarting ${SERVICE_NAME} ..."
sudo systemctl daemon-reload
sudo systemctl enable --now "${SERVICE_NAME}"

# Kill stale listeners if they kept the port (your earlier issue)
if sudo ss -tlnp | grep -q ":${NCPA_PORT}"; then
  # If multiple pids bind, systemd restart alone may not clear it; best effort kill old python on port
  pids="$(sudo ss -tlnp | awk -v p=":${NCPA_PORT}" '$0 ~ p {print $NF}' | sed -E 's/.*pid=([0-9]+).*/\1/' | sort -u)"
  if [[ -n "${pids}" ]]; then
    for pid in ${pids}; do
      # don't kill our current one if systemd already started (best effort)
      sudo kill "${pid}" >/dev/null 2>&1 || true
    done
  fi
fi

sudo systemctl restart "${SERVICE_NAME}"

echo "[*] Quick API check ..."
if [[ "${NCPA_USE_SSL}" == "1" ]]; then
  curl -sk "https://127.0.0.1:${NCPA_PORT}/api/system?token=${NCPA_TOKEN}" | head -c 400; echo
  curl -sk "https://127.0.0.1:${NCPA_PORT}/api/plugins?token=${NCPA_TOKEN}" | head -c 400; echo
else
  curl -s "http://127.0.0.1:${NCPA_PORT}/api/system?token=${NCPA_TOKEN}" | head -c 400; echo
  curl -s "http://127.0.0.1:${NCPA_PORT}/api/plugins?token=${NCPA_TOKEN}" | head -c 400; echo
fi

echo "[OK] Done.
- token set
- allowed_hosts=${ALLOWED_HOSTS}
- ssl=${NCPA_USE_SSL} port=${NCPA_PORT}
- plugins: check_docker_restart_policy, check_docker_swarm_services
"

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

sudo tee ${NCPA_PLUGINS}/check_cpu_temp << 'EOF'
#!/usr/bin/env bash

WARN=${1:-75}
CRIT=${2:-85}

FILE="/sys/class/thermal/thermal_zone0/temp"

[ ! -r "$FILE" ] && echo "UNKNOWN - CPU temp not readable" && exit 3

TEMP=$(awk '{print $1/1000}' "$FILE")

if (( $(echo "$TEMP >= $CRIT" | bc -l) )); then
  echo "CRITICAL - CPU temp ${TEMP}°C | temp=${TEMP};$WARN;$CRIT"
  exit 2
elif (( $(echo "$TEMP >= $WARN" | bc -l) )); then
  echo "WARNING - CPU temp ${TEMP}°C | temp=${TEMP};$WARN;$CRIT"
  exit 1
else
  echo "OK - CPU temp ${TEMP}°C | temp=${TEMP};$WARN;$CRIT"
  exit 0
fi
EOF

sudo tee ${NCPA_PLUGINS}/check_apt_list >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

TIMEOUT=120
MAX_LINES=25
WARN_N=""
CRIT_N=""
SECURITY_SCAN=1

usage() {
  cat <<USAGE
check_apt_list - list available APT updates (no install), mark security updates

Options:
  -t SEC     timeout for the whole check (default: 120)
  -m N       max number of packages to print (default: 25)
  -w N       warning threshold by number of available updates
  -c N       critical threshold by number of available updates
  --no-security-scan   do not classify security updates (faster)
USAGE
}

# --- args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t) TIMEOUT="${2:-}"; shift 2;;
    -m) MAX_LINES="${2:-}"; shift 2;;
    -w) WARN_N="${2:-}"; shift 2;;
    -c) CRIT_N="${2:-}"; shift 2;;
    --no-security-scan) SECURITY_SCAN=0; shift;;
    -h|--help) usage; exit 3;;
    *) echo "UNKNOWN - unknown arg: $1"; usage; exit 3;;
  esac
done

run_timeout() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "${TIMEOUT}" "$@"
  else
    "$@"
  fi
}

# --- collect upgradable packages ---
# We rely on current apt cache. This script does NOT run "apt update".
UPG_LIST="$(run_timeout bash -lc 'LANG=C apt list --upgradable 2>/dev/null | tail -n +2' || true)"

if [[ -z "${UPG_LIST// }" ]]; then
  echo "OK - no updates available |available_upgrades=0;;;0 security_updates=0;;;0"
  exit 0
fi

mapfile -t PKGS < <(printf '%s\n' "$UPG_LIST" | awk -F'/' '{print $1}' | sed 's/ *$//' | grep -v '^$' || true)

TOTAL="${#PKGS[@]}"
SEC=0

# --- detect security updates (best-effort heuristic) ---
# We inspect apt-cache policy output and look for repos containing "security".
declare -A IS_SEC
if [[ "$SECURITY_SCAN" -eq 1 ]]; then
  for p in "${PKGS[@]}"; do
    # policy can be slow on tiny devices; keep it under the global timeout
    out="$(run_timeout apt-cache policy "$p" 2>/dev/null || true)"
    if echo "$out" | grep -Eqi 'security|debian-security|raspbian.*security|ubuntu.*-security'; then
      IS_SEC["$p"]=1
      ((SEC+=1))
    fi
  done
fi

# --- thresholds & exit code ---
RC=0
STATE="OK"

# If explicit thresholds are set, honor them.
if [[ -n "$CRIT_N" && "$TOTAL" -ge "$CRIT_N" ]]; then
  RC=2; STATE="CRITICAL"
elif [[ -n "$WARN_N" && "$TOTAL" -ge "$WARN_N" ]]; then
  RC=1; STATE="WARNING"
else
  # Default policy: any security updates => CRIT, else any updates => WARN
  if [[ "$SECURITY_SCAN" -eq 1 && "$SEC" -gt 0 ]]; then
    RC=2; STATE="CRITICAL"
  else
    RC=1; STATE="WARNING"
  fi
fi

# --- build compact output list ---
PRINT_N="$MAX_LINES"
if [[ "$TOTAL" -lt "$PRINT_N" ]]; then PRINT_N="$TOTAL"; fi

lines=()
for ((i=0; i<PRINT_N; i++)); do
  p="${PKGS[$i]}"
  if [[ "${IS_SEC[$p]:-0}" -eq 1 ]]; then
    lines+=("[SEC] $p")
  else
    lines+=("$p")
  fi
done

EXTRA=""
if [[ "$TOTAL" -gt "$PRINT_N" ]]; then
  EXTRA=" (+$((TOTAL-PRINT_N)) more)"
fi

LIST_OUT="$(printf '%s, ' "${lines[@]}" | sed 's/, $//')${EXTRA}"

if [[ "$SECURITY_SCAN" -eq 0 ]]; then
  echo "$STATE - updates=$TOTAL (security-scan=off): $LIST_OUT |available_upgrades=$TOTAL;;;0"
else
  echo "$STATE - updates=$TOTAL security=$SEC: $LIST_OUT |available_upgrades=$TOTAL;;;0 security_updates=$SEC;;;0"
fi

exit "$RC"
EOF

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

sudo tee "/${NCPA_PLUGINS}/check_ssl_cert_expiry" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

warn_days=21
crit_days=7
file=""
host=""
port="443"
sni=""

usage() {
  echo "Usage:"
  echo "  $0 -f /path/to/cert.pem [-w DAYS] [-c DAYS]"
  echo "  $0 -H host [-p port] [-S sni_name] [-w DAYS] [-c DAYS]"
}

while getopts ":f:H:p:S:w:c:h" opt; do
  case "$opt" in
    f) file="$OPTARG" ;;
    H) host="$OPTARG" ;;
    p) port="$OPTARG" ;;
    S) sni="$OPTARG" ;;
    w) warn_days="$OPTARG" ;;
    c) crit_days="$OPTARG" ;;
    h) usage; exit 3 ;;
    \?) echo "UNKNOWN - invalid option: -$OPTARG"; usage; exit 3 ;;
    :)  echo "UNKNOWN - option -$OPTARG requires an argument"; usage; exit 3 ;;
  esac
done

command -v openssl >/dev/null 2>&1 || { echo "UNKNOWN - openssl not found (install openssl)"; exit 3; }

if [[ -z "$file" && -z "$host" ]]; then
  echo "UNKNOWN - need -f (file) or -H (host)"; usage; exit 3
fi
if [[ -n "$file" && -n "$host" ]]; then
  echo "UNKNOWN - use either -f OR -H, not both"; exit 3
fi

now_epoch="$(date +%s)"

extract_enddate() {
  # supports both: enddate=... and notAfter=...
  sed -n -E 's/^(enddate|notAfter)=//p'
}

get_enddate_from_file() {
  [[ -r "$file" ]] || { echo "UNKNOWN - cannot read cert file: $file"; exit 3; }
  openssl x509 -in "$file" -noout -enddate 2>/dev/null | extract_enddate
}

get_enddate_from_host() {
  local servername="${sni:-$host}"
  timeout 10 openssl s_client -servername "$servername" -connect "${host}:${port}" </dev/null 2>/dev/null \
    | openssl x509 -noout -enddate 2>/dev/null | extract_enddate
}

if [[ -n "$file" ]]; then
  enddate_str="$(get_enddate_from_file || true)"
  mode="file"
  target="$file"
else
  enddate_str="$(get_enddate_from_host || true)"
  mode="host"
  target="${host}:${port}"
fi

if [[ -z "${enddate_str:-}" ]]; then
  echo "UNKNOWN - could not read certificate end date (${mode} ${target})"
  exit 3
fi

end_epoch="$(date -d "$enddate_str" +%s 2>/dev/null || true)"
if [[ -z "$end_epoch" ]]; then
  echo "UNKNOWN - could not parse end date: $enddate_str"
  exit 3
fi

remaining_sec=$(( end_epoch - now_epoch ))
remaining_days=$(( remaining_sec / 86400 ))
perf="days_left=${remaining_days};;;;0"

if (( remaining_days < 0 )); then
  echo "CRITICAL - cert EXPIRED ${remaining_days}d ago (end: $enddate_str) | $perf"
  exit 2
fi
if (( remaining_days <= crit_days )); then
  echo "CRITICAL - cert expires in ${remaining_days}d (end: $enddate_str) | $perf"
  exit 2
elif (( remaining_days <= warn_days )); then
  echo "WARNING - cert expires in ${remaining_days}d (end: $enddate_str) | $perf"
  exit 1
else
  echo "OK - cert valid ${remaining_days}d left (end: $enddate_str) | $perf"
  exit 0
fi
EOF

sudo tee "/${NCPA_PLUGINS}/run_apt_update" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "Starting manual APT update at $(date)"

apt-get update
apt-get -y upgrade
apt-get -y autoremove

echo "APT update finished at $(date)"
EOF

sudo chmod 0755 \
  "${NCPA_PLUGINS}/check_docker_restart_policy" \
  "${NCPA_PLUGINS}/check_ssl_cert_expiry" \
  "${NCPA_PLUGINS}/run_apt_update" \
  "${NCPA_PLUGINS}/check_docker_swarm_services" \
  "${NCPA_PLUGINS}/check_cpu_temp" \
  "${NCPA_PLUGINS}/check_apt_list"

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

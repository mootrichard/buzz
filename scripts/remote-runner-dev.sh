#!/usr/bin/env bash
# Local end-to-end harness for the Remote Runner protocol.
#
# Usage:
#   just remote-runner-dev up
#   just remote-runner-dev pair
#   just remote-runner-dev status
#   just remote-runner-dev logs runner
#   just remote-runner-dev down
#   just remote-runner-dev reset --yes
#
# The harness is deliberately isolated from the normal Buzz development
# database and Redis. Runner identity, deployments, and workspaces persist under
# /tmp by default so `down` + `up` can exercise restart behavior.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

DEV_ROOT="${BUZZ_REMOTE_RUNNER_DEV_ROOT:-/tmp/buzz-remote-runner-dev-$(id -u)}"
ENV_FILE="${DEV_ROOT}/environment"
MARKER_FILE="${DEV_ROOT}/.buzz-remote-runner-dev"
LOG_DIR="${DEV_ROOT}/logs"
PID_DIR="${DEV_ROOT}/pids"
POSTGRES_DIR="${DEV_ROOT}/postgres"
RUNNER_STATE_DIR="${DEV_ROOT}/runner/state"
RUNNER_SECRETS_DIR="${DEV_ROOT}/runner/secrets"
RUNNER_WORKSPACE_DIR="${DEV_ROOT}/runner/workspaces"
RUNNER_RETIRED_DIR="${DEV_ROOT}/runner/retired"

POSTGRES_CONTAINER="buzz-remote-runner-dev-postgres"
REDIS_CONTAINER="buzz-remote-runner-dev-redis"

refresh_effective_config() {
  POSTGRES_PORT="${BUZZ_REMOTE_RUNNER_DEV_POSTGRES_PORT:-55433}"
  REDIS_PORT="${BUZZ_REMOTE_RUNNER_DEV_REDIS_PORT:-56379}"
  RELAY_PORT="${BUZZ_REMOTE_RUNNER_DEV_RELAY_PORT:-3300}"
  HEALTH_PORT="${BUZZ_REMOTE_RUNNER_DEV_HEALTH_PORT:-58080}"
  METRICS_PORT="${BUZZ_REMOTE_RUNNER_DEV_METRICS_PORT:-59102}"
  AGENT_IMAGE="${BUZZ_REMOTE_RUNNER_DEV_AGENT_IMAGE:-buzz-agent:remote-runner-dev}"
  RUNTIME_ALLOWLIST="{\"buzz-agent\":\"${AGENT_IMAGE}\"}"
}
refresh_effective_config

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { printf "${BLUE}[remote-runner-dev]${NC} %s\n" "$*"; }
ok() { printf "${GREEN}[remote-runner-dev]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[remote-runner-dev]${NC} %s\n" "$*" >&2; }
fail() { printf "${RED}[remote-runner-dev]${NC} %s\n" "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Remote Runner local development harness

Usage:
  just remote-runner-dev up [--no-desktop] [--rebuild]
      Start isolated infrastructure, the branch relay, runner, and Desktop.

  just remote-runner-dev pair
      Display the one-time pairing URI and complete the interactive pairing.

  just remote-runner-dev status
      Show service health, protocol version, runner processes, and agent containers.

  just remote-runner-dev logs [relay|runner|desktop] [--follow]
      Show recent logs. With --follow, continue streaming.

  just remote-runner-dev desktop
      Start or reopen the branch Desktop against the isolated relay.

  just remote-runner-dev down
      Stop Desktop, runner, relay, Postgres, and Redis. Preserve runner/database state.

  just remote-runner-dev reset --yes
      Run down, remove only agent containers mounted from this harness, and delete
      the harness database, runner identity, secrets, and workspaces.

Environment overrides:
  BUZZ_REMOTE_RUNNER_DEV_ROOT
  BUZZ_REMOTE_RUNNER_DEV_RELAY_HOST
  BUZZ_REMOTE_RUNNER_DEV_RELAY_PORT
  BUZZ_REMOTE_RUNNER_DEV_POSTGRES_PORT
  BUZZ_REMOTE_RUNNER_DEV_REDIS_PORT
  BUZZ_REMOTE_RUNNER_DEV_HEALTH_PORT
  BUZZ_REMOTE_RUNNER_DEV_METRICS_PORT
  BUZZ_REMOTE_RUNNER_DEV_AGENT_IMAGE
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

ensure_tools() {
  require_command cargo
  require_command curl
  require_command docker
  require_command git
  require_command node
  require_command pnpm
  require_command python3
  docker info >/dev/null 2>&1 || fail "Docker daemon is not available"
}

detect_relay_host() {
  if [[ -n "${BUZZ_REMOTE_RUNNER_DEV_RELAY_HOST:-}" ]]; then
    printf '%s\n' "${BUZZ_REMOTE_RUNNER_DEV_RELAY_HOST}"
    return
  fi

  local address=""
  case "$(uname -s)" in
    Darwin)
      address="$(ipconfig getifaddr en0 2>/dev/null || true)"
      [[ -n "${address}" ]] || address="$(ipconfig getifaddr en1 2>/dev/null || true)"
      ;;
    Linux)
      address="$(hostname -I 2>/dev/null | awk '{print $1}')"
      ;;
  esac
  [[ -n "${address}" ]] || fail \
    "Could not detect a LAN address; set BUZZ_REMOTE_RUNNER_DEV_RELAY_HOST"
  printf '%s\n' "${address}"
}

ensure_state_root() {
  if [[ -e "${DEV_ROOT}" ]]; then
    python3 - "${DEV_ROOT}" "${MARKER_FILE}" <<'PY'
import os
import stat
import sys

path, marker = sys.argv[1:]
metadata = os.lstat(path)
if stat.S_ISLNK(metadata.st_mode):
    raise SystemExit(f"refusing symlinked development root: {path}")
if not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit(f"development root is not a directory: {path}")
if metadata.st_uid != os.getuid():
    raise SystemExit(f"development root is not owned by the current user: {path}")
if os.path.lexists(marker):
    marker_metadata = os.lstat(marker)
    if (
        not stat.S_ISREG(marker_metadata.st_mode)
        or marker_metadata.st_uid != os.getuid()
        or marker_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise SystemExit(f"invalid harness marker: {marker}")
elif os.listdir(path):
    raise SystemExit(
        f"refusing nonempty development root without the harness marker: {path}"
    )
PY
  fi
  mkdir -p \
    "${DEV_ROOT}" \
    "${LOG_DIR}" \
    "${PID_DIR}" \
    "${POSTGRES_DIR}" \
    "${RUNNER_STATE_DIR}" \
    "${RUNNER_SECRETS_DIR}" \
    "${RUNNER_WORKSPACE_DIR}" \
    "${RUNNER_RETIRED_DIR}"
  chmod 0700 "${DEV_ROOT}"
  if [[ ! -f "${MARKER_FILE}" ]]; then
    printf 'remote-runner-dev\n' >"${MARKER_FILE}"
    chmod 0600 "${MARKER_FILE}"
  fi
}

write_environment() {
  local relay_host="$1"
  local relay_url="ws://${relay_host}:${RELAY_PORT}"
  umask 077
  {
    printf 'export BUZZ_REMOTE_RUNNER_DEV_RELAY_HOST=%q\n' "${relay_host}"
    printf 'export BUZZ_REMOTE_RUNNER_DEV_RELAY_URL=%q\n' "${relay_url}"
    printf 'export BUZZ_REMOTE_RUNNER_DEV_ROOT=%q\n' "${DEV_ROOT}"
    printf 'export BUZZ_REMOTE_RUNNER_DEV_RELAY_PORT=%q\n' "${RELAY_PORT}"
    printf 'export BUZZ_REMOTE_RUNNER_DEV_POSTGRES_PORT=%q\n' "${POSTGRES_PORT}"
    printf 'export BUZZ_REMOTE_RUNNER_DEV_REDIS_PORT=%q\n' "${REDIS_PORT}"
    printf 'export BUZZ_REMOTE_RUNNER_DEV_HEALTH_PORT=%q\n' "${HEALTH_PORT}"
    printf 'export BUZZ_REMOTE_RUNNER_DEV_METRICS_PORT=%q\n' "${METRICS_PORT}"
    printf 'export BUZZ_REMOTE_RUNNER_DEV_AGENT_IMAGE=%q\n' "${AGENT_IMAGE}"
  } >"${ENV_FILE}"
}

load_environment() {
  [[ -f "${ENV_FILE}" ]] || fail \
    "Harness is not configured. Run: just remote-runner-dev up"
  [[ -f "${MARKER_FILE}" ]] || fail \
    "Refusing to load configuration without the harness marker"
  python3 - "${DEV_ROOT}" "${ENV_FILE}" <<'PY'
import os
import stat
import sys

root, environment = sys.argv[1:]
root_metadata = os.lstat(root)
environment_metadata = os.lstat(environment)
if stat.S_ISLNK(root_metadata.st_mode) or stat.S_ISLNK(environment_metadata.st_mode):
    raise SystemExit("refusing symlinked harness configuration")
if root_metadata.st_uid != os.getuid() or environment_metadata.st_uid != os.getuid():
    raise SystemExit("harness configuration is not owned by the current user")
if environment_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
    raise SystemExit("harness configuration is writable by another user")
PY
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  refresh_effective_config
}

container_exists() {
  docker inspect "$1" >/dev/null 2>&1
}

container_is_running() {
  [[ "$(docker inspect --format '{{.State.Running}}' "$1" 2>/dev/null || true)" == "true" ]]
}

assert_owned_container() {
  local container="$1"
  local owner
  owner="$(docker inspect --format '{{index .Config.Labels "com.buzz.test"}}' \
    "${container}" 2>/dev/null || true)"
  [[ "${owner}" == "remote-runner-dev" ]] || fail \
    "Refusing to modify container ${container}: ownership label is missing"
}

start_postgres() {
  if container_exists "${POSTGRES_CONTAINER}"; then
    assert_owned_container "${POSTGRES_CONTAINER}"
    if ! container_is_running "${POSTGRES_CONTAINER}"; then
      docker start "${POSTGRES_CONTAINER}" >/dev/null
    fi
  else
    docker run -d \
      --name "${POSTGRES_CONTAINER}" \
      --label com.buzz.test=remote-runner-dev \
      -e POSTGRES_USER=buzz \
      -e POSTGRES_PASSWORD=buzz_dev \
      -e POSTGRES_DB=buzz \
      -v "${POSTGRES_DIR}:/var/lib/postgresql/data" \
      -p "127.0.0.1:${POSTGRES_PORT}:5432" \
      postgres:17-alpine >/dev/null
  fi

  for _ in $(seq 1 40); do
    if docker exec "${POSTGRES_CONTAINER}" pg_isready -U buzz >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  fail "Postgres did not become ready; inspect ${POSTGRES_CONTAINER}"
}

start_redis() {
  if container_exists "${REDIS_CONTAINER}"; then
    assert_owned_container "${REDIS_CONTAINER}"
    if ! container_is_running "${REDIS_CONTAINER}"; then
      docker start "${REDIS_CONTAINER}" >/dev/null
    fi
  else
    docker run -d \
      --name "${REDIS_CONTAINER}" \
      --label com.buzz.test=remote-runner-dev \
      -p "127.0.0.1:${REDIS_PORT}:6379" \
      redis:7-alpine >/dev/null
  fi

  for _ in $(seq 1 20); do
    if docker exec "${REDIS_CONTAINER}" redis-cli ping 2>/dev/null | grep -q PONG; then
      return
    fi
    sleep 1
  done
  fail "Redis did not become ready; inspect ${REDIS_CONTAINER}"
}

pid_file() {
  printf '%s/%s.pid\n' "${PID_DIR}" "$1"
}

log_file() {
  printf '%s/%s.log\n' "${LOG_DIR}" "$1"
}

process_is_running() {
  local name="$1"
  local file
  file="$(pid_file "${name}")"
  [[ -f "${file}" ]] || return 1
  local pid
  pid="$(<"${file}")"
  [[ "${pid}" =~ ^[0-9]+$ ]] && kill -0 "${pid}" >/dev/null 2>&1
}

start_background() {
  local name="$1"
  shift
  if process_is_running "${name}"; then
    ok "${name} already running (pid $(<"$(pid_file "${name}")"))"
    return
  fi

  local file log_path
  file="$(pid_file "${name}")"
  log_path="$(log_file "${name}")"
  rm -f "${file}"
  python3 - "${file}" "${log_path}" "$@" <<'PY'
import os
import subprocess
import sys

pid_file, log_file, *command = sys.argv[1:]
with open(log_file, "ab", buffering=0) as output:
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=output,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        close_fds=True,
    )
with open(pid_file, "w", encoding="utf-8") as handle:
    handle.write(f"{process.pid}\n")
PY
  sleep 1
  process_is_running "${name}" || fail \
    "${name} exited during startup; inspect $(log_file "${name}")"
  ok "Started ${name} (pid $(<"${file}"))"
}

stop_background() {
  local name="$1"
  local file
  file="$(pid_file "${name}")"
  [[ -f "${file}" ]] || return 0
  local pid
  pid="$(<"${file}")"
  if [[ "${pid}" =~ ^[0-9]+$ ]] && kill -0 "${pid}" >/dev/null 2>&1; then
    kill -TERM -- "-${pid}" >/dev/null 2>&1 || kill -TERM "${pid}" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
      kill -0 "${pid}" >/dev/null 2>&1 || break
      sleep 0.25
    done
    if kill -0 "${pid}" >/dev/null 2>&1; then
      warn "${name} did not stop after 5 seconds; sending KILL"
      kill -KILL -- "-${pid}" >/dev/null 2>&1 || kill -KILL "${pid}" >/dev/null 2>&1 || true
    fi
  fi
  rm -f "${file}"
}

port_is_listening() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
  else
    curl --silent --max-time 1 "http://127.0.0.1:${port}/" >/dev/null 2>&1
  fi
}

assert_port_available() {
  local service="$1"
  local port="$2"
  if port_is_listening "${port}" && ! process_is_running "${service}"; then
    fail "Port ${port} is already occupied by a process outside this harness"
  fi
}

build_components() {
  local rebuild="$1"
  log "Building branch relay, admin CLI, and runner..."
  cargo build -p buzz-relay -p buzz-admin -p buzz-runner

  local revision current_revision=""
  revision="$(git rev-parse HEAD)"
  if docker image inspect "${AGENT_IMAGE}" >/dev/null 2>&1; then
    current_revision="$(docker image inspect \
      --format '{{index .Config.Labels "com.buzz.source-revision"}}' \
      "${AGENT_IMAGE}" 2>/dev/null || true)"
  fi
  if [[ "${rebuild}" == "true" || "${current_revision}" != "${revision}" ]]; then
    log "Building Sprig agent runtime image ${AGENT_IMAGE}..."
    docker build \
      --label "com.buzz.source-revision=${revision}" \
      --tag "${AGENT_IMAGE}" \
      --file Dockerfile.agent \
      .
  else
    ok "Agent runtime image already matches ${revision:0:8}"
  fi
}

apply_schema() {
  local relay_url="$1"
  log "Applying migrations and seeding ${relay_url}..."
  env \
    DATABASE_URL="postgres://buzz:buzz_dev@127.0.0.1:${POSTGRES_PORT}/buzz" \
    PGHOST=127.0.0.1 \
    PGPORT="${POSTGRES_PORT}" \
    PGUSER=buzz \
    PGPASSWORD=buzz_dev \
    PGDATABASE=buzz \
    RELAY_URL="${relay_url}" \
    ./target/debug/buzz-admin migrate
  env \
    PGHOST=127.0.0.1 \
    PGPORT="${POSTGRES_PORT}" \
    PGUSER=buzz \
    PGPASSWORD=buzz_dev \
    PGDATABASE=buzz \
    RELAY_URL="${relay_url}" \
    ./scripts/seed-local-community.sh
}

start_relay() {
  local relay_url="$1"
  assert_port_available relay "${RELAY_PORT}"
  assert_port_available relay "${HEALTH_PORT}"
  assert_port_available relay "${METRICS_PORT}"
  start_background relay env \
    DATABASE_URL="postgres://buzz:buzz_dev@127.0.0.1:${POSTGRES_PORT}/buzz" \
    REDIS_URL="redis://127.0.0.1:${REDIS_PORT}" \
    RELAY_URL="${relay_url}" \
    BUZZ_BIND_ADDR="0.0.0.0:${RELAY_PORT}" \
    BUZZ_HEALTH_PORT="${HEALTH_PORT}" \
    BUZZ_METRICS_PORT="${METRICS_PORT}" \
    ./target/debug/buzz-relay

  for _ in $(seq 1 60); do
    if curl --silent --fail --max-time 1 \
      "http://127.0.0.1:${HEALTH_PORT}/_readiness" >/dev/null; then
      ok "Relay ready at ${relay_url}"
      return
    fi
    sleep 1
  done
  fail "Relay did not become ready; inspect $(log_file relay)"
}

start_runner() {
  local relay_url="$1"
  start_background runner env \
    BUZZ_RELAY_URL="${relay_url}" \
    BUZZ_RUNNER_STATE_DIR="${RUNNER_STATE_DIR}" \
    BUZZ_RUNNER_SECRETS_DIR="${RUNNER_SECRETS_DIR}" \
    BUZZ_RUNNER_WORKSPACE_DIR="${RUNNER_WORKSPACE_DIR}" \
    BUZZ_RUNNER_RETIRED_DIR="${RUNNER_RETIRED_DIR}" \
    BUZZ_RUNNER_RUNTIMES="${RUNTIME_ALLOWLIST}" \
    RUST_LOG=buzz_runner=info \
    ./target/debug/buzz-runner run --relay "${relay_url}"
}

start_desktop() {
  ensure_tools
  load_environment
  if process_is_running desktop; then
    ok "Desktop already running (pid $(<"$(pid_file desktop)"))"
    return
  fi
  start_background desktop env \
    BUZZ_RELAY_URL="${BUZZ_REMOTE_RUNNER_DEV_RELAY_URL}" \
    just desktop-standalone
  ok "Desktop is launching; logs: $(log_file desktop)"
}

command_up() {
  local launch_desktop=true
  local rebuild=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-desktop) launch_desktop=false ;;
      --rebuild) rebuild=true ;;
      -h|--help) usage; return ;;
      *) fail "Unknown up option: $1" ;;
    esac
    shift
  done

  ensure_tools
  if [[ -f "${ENV_FILE}" ]]; then
    load_environment
  fi
  ensure_state_root
  stop_background desktop
  stop_background runner
  stop_background relay
  local relay_host relay_url
  relay_host="$(detect_relay_host)"
  relay_url="ws://${relay_host}:${RELAY_PORT}"
  write_environment "${relay_host}"

  log "Using isolated state at ${DEV_ROOT}"
  log "Using relay URL ${relay_url}"
  start_postgres
  start_redis
  build_components "${rebuild}"
  apply_schema "${relay_url}"
  start_relay "${relay_url}"
  start_runner "${relay_url}"
  if [[ "${launch_desktop}" == "true" ]]; then
    start_desktop
  fi

  printf '\n'
  ok "Remote Runner development stack is up"
  printf '  Pair:   just remote-runner-dev pair\n'
  printf '  Status: just remote-runner-dev status\n'
  printf '  Logs:   just remote-runner-dev logs runner --follow\n'
  printf '  Stop:   just remote-runner-dev down\n'
}

command_pair() {
  ensure_tools
  load_environment
  [[ -x ./target/debug/buzz-runner ]] || fail \
    "Runner binary is missing. Run: just remote-runner-dev up"
  env \
    BUZZ_RELAY_URL="${BUZZ_REMOTE_RUNNER_DEV_RELAY_URL}" \
    BUZZ_RUNNER_STATE_DIR="${RUNNER_STATE_DIR}" \
    BUZZ_RUNNER_SECRETS_DIR="${RUNNER_SECRETS_DIR}" \
    BUZZ_RUNNER_WORKSPACE_DIR="${RUNNER_WORKSPACE_DIR}" \
    BUZZ_RUNNER_RETIRED_DIR="${RUNNER_RETIRED_DIR}" \
    BUZZ_RUNNER_RUNTIMES="${RUNTIME_ALLOWLIST}" \
    ./target/debug/buzz-runner pair --relay "${BUZZ_REMOTE_RUNNER_DEV_RELAY_URL}"
}

component_status() {
  local name="$1"
  if process_is_running "${name}"; then
    printf '  %-9s running (pid %s)\n' "${name}" "$(<"$(pid_file "${name}")")"
  else
    printf '  %-9s stopped\n' "${name}"
  fi
}

container_status() {
  local container="$1"
  if container_exists "${container}"; then
    docker inspect --format '{{.State.Status}}' "${container}"
  else
    printf 'absent\n'
  fi
}

command_status() {
  ensure_tools
  if [[ -f "${ENV_FILE}" ]]; then
    load_environment
  else
    BUZZ_REMOTE_RUNNER_DEV_RELAY_URL="not configured"
  fi
  printf 'Remote Runner development stack\n'
  printf '  relay URL %s\n' "${BUZZ_REMOTE_RUNNER_DEV_RELAY_URL}"
  component_status relay
  component_status runner
  component_status desktop
  printf '  %-9s %s\n' postgres "$(container_status "${POSTGRES_CONTAINER}")"
  printf '  %-9s %s\n' redis "$(container_status "${REDIS_CONTAINER}")"

  if [[ "${BUZZ_REMOTE_RUNNER_DEV_RELAY_URL}" != "not configured" ]]; then
    local http_url="${BUZZ_REMOTE_RUNNER_DEV_RELAY_URL/ws:/http:}"
    local protocol response
    response="$(curl --silent --max-time 2 \
      -H 'Accept: application/nostr+json' "${http_url}" 2>/dev/null || true)"
    protocol="$(python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("buzz", {}).get("remote_runner_protocol", "unavailable"))
except Exception:
    print("unavailable")' <<<"${response}")"
    printf '  protocol  %s\n' "${protocol}"
  fi

  printf '\nAgent containers scoped to %s:\n' "${RUNNER_WORKSPACE_DIR}"
  local found=false container source
  while IFS= read -r container; do
    [[ -n "${container}" ]] || continue
    source="$(docker inspect --format \
      '{{range .Mounts}}{{if eq .Destination "/workspace"}}{{.Source}}{{end}}{{end}}' \
      "${container}" 2>/dev/null || true)"
    if is_scoped_workspace_source "${source}"; then
      found=true
      docker ps -a --filter "id=${container}" \
        --format '  {{.Names}}  {{.Status}}  {{.Image}}'
    fi
  done < <(docker ps -aq --filter label=com.buzz.agent)
  [[ "${found}" == "true" ]] || printf '  none\n'
}

command_logs() {
  local component="${1:-runner}"
  local follow=false
  if [[ $# -gt 0 ]]; then
    shift
  fi
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --follow|-f) follow=true ;;
      *) fail "Unknown logs option: $1" ;;
    esac
    shift
  done
  case "${component}" in
    relay|runner|desktop) ;;
    *) fail "Log component must be relay, runner, or desktop" ;;
  esac
  local file
  file="$(log_file "${component}")"
  [[ -f "${file}" ]] || fail "No ${component} log exists yet"
  if [[ "${follow}" == "true" ]]; then
    tail -n 100 -f "${file}"
  else
    tail -n 100 "${file}"
  fi
}

is_scoped_workspace_source() {
  local source="$1"
  [[ -n "${source}" ]] || return 1
  local actual expected
  actual="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${source}")"
  expected="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' \
    "${RUNNER_WORKSPACE_DIR}")"
  [[ "${actual}" == "${expected}/"* ]]
}

stop_owned_container() {
  local container="$1"
  if container_exists "${container}"; then
    assert_owned_container "${container}"
    docker stop "${container}" >/dev/null
  fi
}

command_down() {
  stop_background desktop
  stop_background runner
  stop_background relay
  stop_owned_container "${REDIS_CONTAINER}"
  stop_owned_container "${POSTGRES_CONTAINER}"
  ok "Stopped the development stack; database and runner state were preserved"
}

remove_scoped_agent_containers() {
  local container source
  while IFS= read -r container; do
    [[ -n "${container}" ]] || continue
    source="$(docker inspect --format \
      '{{range .Mounts}}{{if eq .Destination "/workspace"}}{{.Source}}{{end}}{{end}}' \
      "${container}" 2>/dev/null || true)"
    if is_scoped_workspace_source "${source}"; then
      docker rm -f "${container}" >/dev/null
    fi
  done < <(docker ps -aq --filter label=com.buzz.agent)
}

remove_owned_container() {
  local container="$1"
  if container_exists "${container}"; then
    assert_owned_container "${container}"
    docker rm -f "${container}" >/dev/null
  fi
}

command_reset() {
  require_command docker
  require_command python3
  [[ "${1:-}" == "--yes" ]] || fail \
    "Reset permanently deletes this harness's database, identity, secrets, and workspaces. Re-run with --yes."
  [[ -e "${DEV_ROOT}" ]] || fail \
    "No Remote Runner development state exists at ${DEV_ROOT}"
  [[ -e "${MARKER_FILE}" || -L "${MARKER_FILE}" ]] || fail \
    "Refusing reset because ${DEV_ROOT} does not contain the harness marker"
  python3 - "${DEV_ROOT}" "${MARKER_FILE}" <<'PY'
import os
import stat
import sys

path, marker = sys.argv[1:]
metadata = os.lstat(path)
if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit(f"refusing unsafe development root: {path}")
if metadata.st_uid != os.getuid():
    raise SystemExit(f"development root is not owned by the current user: {path}")
actual = os.path.realpath(path)
if actual in {os.path.sep, os.path.realpath(os.path.expanduser("~"))}:
    raise SystemExit(f"refusing unsafe development root: {path}")
marker_metadata = os.lstat(marker)
if (
    not stat.S_ISREG(marker_metadata.st_mode)
    or marker_metadata.st_uid != os.getuid()
    or marker_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
):
    raise SystemExit(f"invalid harness marker: {marker}")
PY
  command_down
  remove_scoped_agent_containers
  remove_owned_container "${REDIS_CONTAINER}"
  remove_owned_container "${POSTGRES_CONTAINER}"
  rm -rf -- "${DEV_ROOT}"
  ok "Removed Remote Runner development state at ${DEV_ROOT}"
}

command="${1:-help}"
if [[ $# -gt 0 ]]; then
  shift
fi
case "${command}" in
  up) command_up "$@" ;;
  pair) command_pair "$@" ;;
  status) command_status "$@" ;;
  logs) command_logs "$@" ;;
  desktop) start_desktop "$@" ;;
  down) command_down "$@" ;;
  reset) command_reset "$@" ;;
  help|-h|--help) usage ;;
  *) fail "Unknown command: ${command}. Run with --help for usage." ;;
esac

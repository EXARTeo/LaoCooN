#!/usr/bin/env bash
# Smoke test of a running Laocoon stack (the proxy in front of the original eClass). Used by
# deploy/deploy.sh (native). Waits up to $SMOKE_TIMEOUT seconds (default 90) for both services to come up.
#
#   deploy/smoke.sh [proxy-url] [eclass-url]        defaults: http://127.0.0.1:9000 http://127.0.0.1:8081
#
# With COMPOSE_FILE set (Docker) it also checks, from inside the eClass container, that eClass reaches the proxy
# over the stack's network (the path every chat request takes).
set -euo pipefail
PROXY="${1:-http://127.0.0.1:9000}"
ECLASS="${2:-http://127.0.0.1:8081}"
TIMEOUT="${SMOKE_TIMEOUT:-90}"

fail() { echo "smoke: FAIL  $*" >&2; exit 1; }
status() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" || true; }
expect() {   # description wanted-status curl-args...
  local what=$1 want=$2 got; shift 2
  got="$(status "$@")"
  [ "$got" = "$want" ] || fail "$what: HTTP $got, expected $want"
  echo "smoke: ok    $what (HTTP $got)"
}

wait_for() {   # description url
  local i
  for ((i = 0; i < TIMEOUT; i += 2)); do
    curl -fs -o /dev/null --max-time 5 "$2" && return 0
    sleep 2
  done
  fail "$1 did not come up within ${TIMEOUT}s ($2)"
}
wait_for "the proxy" "$PROXY/health"
wait_for "eClass" "$ECLASS/login"

health="$(curl -fsS --max-time 10 "$PROXY/health")" || fail "proxy /health unreachable at $PROXY"
grep -Eq '"ok": ?true' <<<"$health" || fail "proxy /health: $health"
grep -Eq '"enabled": ?true' <<<"$health" || fail "proxy runs with LAOCOON_ENABLED=false: $health"
echo "smoke: ok    proxy health ($health)"
# the console: its API refuses a request without a session or the token; its pages send the browser to sign in
expect "proxy console API requires a session or the token" 401 "$PROXY/laocoon/api/state"
loc="$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 10 "$PROXY/laocoon" || true)"
[[ "$loc" == "302 "*"/laocoon/login?next="* ]] || fail "proxy console page without a session: '$loc', expected a 302 to /laocoon/login"
echo "smoke: ok    proxy console page sends the browser to sign in (HTTP 302)"
expect "proxy sign-in page" 200 "$PROXY/laocoon/login"
reply="$(curl -s --max-time 10 -X POST -H 'Content-Type: application/json' -d '{"messages":[]}' \
  "$PROXY/v1/chat/completions" || true)"
grep -q 'invalid Laocoon app key' <<<"$reply" || fail "proxy /v1 without the app key: $reply (is LAOCOON_APP_KEY set?)"
echo "smoke: ok    proxy /v1 rejects requests without the app key"
expect "eClass login page" 200 "$ECLASS/login"

if [ -n "${COMPOSE_FILE:-}" ]; then
  docker compose exec -T eclass-original python -c \
    "import urllib.request; urllib.request.urlopen('http://laocoon-proxy:9000/health', timeout=5)" \
    || fail "eClass cannot reach the proxy inside the stack"
  echo "smoke: ok    eClass -> proxy inside the stack"
fi
echo "smoke: all checks passed"

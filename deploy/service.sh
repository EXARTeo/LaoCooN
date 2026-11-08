#!/usr/bin/env bash
# Entry point of the systemd user services of the native server deploy (deploy/deploy.sh, deploy/systemd/).
#
#   deploy/service.sh mockllm|proxy|eclass    run one service in the foreground (systemd supervises it)
#   deploy/service.sh llm-mode                print "mock" or "real" for the current settings
#
# Settings: $LAOCOON_DEPLOY_ROOT/shared/settings.env (see deploy/server.env.example).
set -euo pipefail
REL="$(cd "$(dirname "$0")/.." && pwd -P)"          # this release, <root>/releases/<name> (systemd: <root>/current)
ROOT="${LAOCOON_DEPLOY_ROOT:-${ODYSSEUS_DEPLOY_ROOT:-$(dirname "$(dirname "$REL")")}}"   # the deploy root, whatever deploy.sh used
SETTINGS="$ROOT/shared/settings.env"
[ -f "$SETTINGS" ] || { echo "missing $SETTINGS (run deploy/deploy.sh first)" >&2; exit 1; }
set -a
# shellcheck source=/dev/null  # the settings file (deploy/server.env.example)
. "$SETTINGS"
set +a
# Settings written before the rename use ODYSSEUS_* names: they still apply, and a LAOCOON_* value wins. (The file
# is not rewritten, so a rollback to a release from before the rename still finds its names.)
for k in $(compgen -e | grep '^ODYSSEUS_' || true); do
  n="LAOCOON_${k#ODYSSEUS_}"
  [ -n "${!n:-}" ] || export "$n=${!k}"
done
PY="$REL/.venv/bin"
DATA="$ROOT/data"
POLICIES="$ROOT/shared/policies"                    # the server's policy and the studio's drafts (sync_policy)
BIND="${BIND_ADDR:?BIND_ADDR is not set in $SETTINGS}"
PP="${PROXY_PORT:-9100}"
EP="${ECLASS_PORT:-8181}"
MP="${MOCK_PORT:-8998}"

mode="${LLM_MODE:-auto}"
if [ "$mode" = auto ]; then
  case "${AI_STUDIO_API_KEY:-}" in ""|your-key-here) mode=mock ;; *) mode=real ;; esac
fi
if [ "$mode" = mock ]; then
  UP_URL="http://127.0.0.1:$MP/v1" UP_KEY=mock UP_MODEL=mock-compromised
else
  UP_URL="${LAOCOON_UPSTREAM_BASE_URL:-https://generativelanguage.googleapis.com/v1beta/openai}"
  UP_KEY="${AI_STUDIO_API_KEY:-}" UP_MODEL="${GEMINI_MODEL:-gemini-3.5-flash-lite}"
fi
GUNICORN=(--workers 2 --threads 4 --timeout 180 --access-logfile -)

# The proxy's policy lives on the server (shared/policies/eclass.yaml), not in a release: deploys and rollbacks swap
# releases and prune old ones, the policy stays. The first start copies the release's policies/eclass.yaml there.
# While nobody edits the server's copy it follows the repository: a start whose release ships another policy (a
# deploy or a rollback) updates it. Once edited on the server it is kept as it is, and a start whose release ships
# another policy says so in the journal. .eclass.yaml.repo holds the repository version the copy was last taken from.
sync_policy() {   # release-policy server-policy
  local repo=$1 pol=$2 base
  base="$(dirname "$2")/.$(basename "$2").repo"
  mkdir -p "$(dirname "$pol")"
  if [ ! -e "$pol" ]; then
    cp "$repo" "$pol.tmp"
    mv -f "$pol.tmp" "$pol"
    cp "$repo" "$base"
    echo "policy: created $pol from the release" >&2
  elif cmp -s "$pol" "$repo"; then
    cmp -s "$repo" "$base" || cp "$repo" "$base"
  elif cmp -s "$pol" "$base"; then
    cp "$repo" "$pol.tmp"
    mv -f "$pol.tmp" "$pol"
    cp "$repo" "$base"
    echo "policy: updated $pol to the release's version (it had not been edited on the server)" >&2
  elif cmp -s "$repo" "$base"; then
    echo "policy: $pol was edited on the server; kept" >&2
  else
    echo "policy: WARNING: $pol was edited on the server and is kept, but this release ships a different" \
         "policy. Its changes: diff $base $repo; once merged into $pol: cp $repo $base" >&2
  fi
}

case "${1:-}" in
  llm-mode)
    echo "$mode" ;;
  mockllm)
    cd "$REL"
    exec "$PY/python" -m eval.mockllm --port "$MP" ;;
  proxy)
    mkdir -p "$DATA"
    # the audit database was odysseus-proxy.db before the rename: the first start copies it (the old service is
    # stopped by then) and leaves the original for a rollback
    if [ ! -e "$DATA/laocoon-proxy.db" ] && [ -e "$DATA/odysseus-proxy.db" ]; then
      for f in "$DATA"/odysseus-proxy.db*; do cp -p "$f" "$DATA/laocoon-${f##*/odysseus-}"; done
    fi
    # LAOCOON_POLICY in the settings wins; otherwise the server's own copy in shared/policies (sync_policy)
    if [ -z "${LAOCOON_POLICY:-}" ]; then
      LAOCOON_POLICY="$POLICIES/eclass.yaml"
      sync_policy "$REL/policies/eclass.yaml" "$LAOCOON_POLICY"
    fi
    [ -f "$LAOCOON_POLICY" ] || { echo "policy: $LAOCOON_POLICY does not exist" >&2; exit 1; }
    echo "policy: $LAOCOON_POLICY" >&2
    cd "$REL"
    binds=(--bind "127.0.0.1:$PP")
    [ "$BIND" = 127.0.0.1 ] || binds+=(--bind "$BIND:$PP")
    export LAOCOON_POLICY LAOCOON_POLICY_DRAFTS="${LAOCOON_POLICY_DRAFTS:-$POLICIES/drafts}" \
      LAOCOON_DB="$DATA/laocoon-proxy.db" \
      LAOCOON_ECLASS_DB="$DATA/eclass-original.db" LAOCOON_IDENTITY=system_prompt \
      LAOCOON_UPSTREAM_BASE_URL="$UP_URL" LAOCOON_UPSTREAM_API_KEY="$UP_KEY" LAOCOON_UPSTREAM_MODEL="$UP_MODEL" \
      LAOCOON_GUARD_API_KEY="${LAOCOON_GUARD_API_KEY:-${TYPESAFE_API_KEY:-}}" \
      LAOCOON_APP_URL="${LAOCOON_APP_URL:-http://$BIND:$EP}"
    exec "$PY/gunicorn" laocoon.proxy:app "${binds[@]}" "${GUNICORN[@]}" ;;
  eclass)                                              # the organisers' eClass, configured only through env
    mkdir -p "$DATA"
    cd "$ROOT/eclass-original"
    export DB_PATH="$DATA/eclass-original.db" LLM_PROVIDER=openai LLM_BASE_URL="http://127.0.0.1:$PP/v1" \
      LLM_API_KEY="${LAOCOON_APP_KEY:?}" LLM_MODEL="$UP_MODEL" SECRET_KEY="${SECRET_KEY:?}" \
      SHOW_TOOL_CALLS="${SHOW_TOOL_CALLS:-false}"
    if [ "${RESET_DB:-true}" = true ]; then "$PY/python" -m app.seed --reset; else "$PY/python" -m app.seed; fi
    exec "$PY/gunicorn" app.app:app --bind "$BIND:$EP" "${GUNICORN[@]}" ;;
  *)
    echo "usage: $0 mockllm|proxy|eclass|llm-mode" >&2
    exit 2 ;;
esac

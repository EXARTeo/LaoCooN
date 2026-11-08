#!/usr/bin/env bash
# Run the whole Laocoon demo natively (no Docker needed).
#
#   scripts/run_local.sh            # real LLM: AI_STUDIO_API_KEY (or LLM_*) from LaoCooN/.env or ../llm-hackathon-26/.env
#                                     (the organisers' checkout: only its .env and git objects are used)
#   scripts/run_local.sh --mock     # offline: scripted "always-fooled" demo model (exact demo prompts only)
#   scripts/run_local.sh stop
#
#   :8081  ORIGINAL eClass (bb54fc3, no code change) -> :9000 proxy
#   :9000  Laocoon proxy                            console: /laocoon?token=$LAOCOON_CONSOLE_TOKEN
#   the "before" for the demo: switch "laocoon.enabled" off on the console's mitigations page; the proxy then
#   forwards every request to the model untouched
#
#   ② Siren Guard (the guardrail classifier) is off unless configured. Put these in LaoCooN/.env (gitignored):
#     TYPESAFE_API_KEY=...                                   Jev (TypeSafe System One), model jev-latest
#     LAOCOON_GUARD_BACKEND=openai LAOCOON_GUARD_MODEL=llama3.2 [LAOCOON_GUARD_BASE_URL=http://127.0.0.1:11434/v1]
#                                                            a local OpenAI-compatible judge (Ollama, llama.cpp, vLLM, LM Studio)
#     LAOCOON_GUARD_BACKEND=hf [LAOCOON_GUARD_MODEL=protectai/deberta-v3-base-prompt-injection-v2]
#                                                            a Hugging Face model in-process (needs: pip install transformers torch)
#     also: LAOCOON_GUARD_TIMEOUT, LAOCOON_GUARD_LABELS (hf label -> policy class map),
#           LAOCOON_GUARD_POINTS=G2,G2b (consult the classifier only there; recommended for hf, whose default
#           model is English-only and would block Greek requests at G1)
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"          # LaoCooN/
HACK="$(dirname "$HERE")"
ORGS="$HACK/llm-hackathon-26"                     # the organisers' repo, if present: its .env (keys), its git objects
ORIG="$HACK/eclass-original"
VENV="${VENV:-$HACK/.venv}"
RUN="$HACK/.run"
DATA="$HACK/.data"
mkdir -p "$RUN" "$DATA"
# Bind address and ports (defaults unchanged). For a localhost-only run on high ports, e.g.:
#   BIND_HOST=127.0.0.1 PORT_ORIG=48081 PORT_PROXY=49000 PORT_MOCK=48999 scripts/run_local.sh --mock
BIND_HOST="${BIND_HOST:-0.0.0.0}"
PORT_ORIG="${PORT_ORIG:-8081}"
PORT_PROXY="${PORT_PROXY:-9000}" PORT_MOCK="${PORT_MOCK:-8999}"

stop() {
  for f in "$RUN"/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null || true; rm -f "$f"; done
  echo "stopped"
}
[ "${1:-}" = "stop" ] && { stop; exit 0; }
stop >/dev/null

[ -x "$VENV/bin/python" ] || python3 -m venv "$VENV"
# every run: an existing venv may predate a new dependency (cryptography, ruamel.yaml); a no-op when up to date
"$VENV/bin/pip" install -q --disable-pip-version-check -r "$HERE/requirements-dev.txt"
if [ ! -d "$ORIG/app" ]; then           # the organisers' eClass at bb54fc3, never modified
  if [ -d "$ORGS/.git" ]; then git -C "$ORGS" worktree add --detach "$ORIG" bb54fc3
  else git clone -q https://github.com/StefanosChaliasos/llm-hackathon-26 "$ORIG" && git -C "$ORIG" checkout -q bb54fc3
  fi
fi

# LLM and classifier settings: the organisers' .env, then LaoCooN/.env (both gitignored; later wins)
for f in "$ORGS/.env" "$HERE/.env"; do
  [ -f "$f" ] && { set -a; . "$f"; set +a; } || true
done
for k in $(compgen -e | grep '^ODYSSEUS_' || true); do   # names from before the rename still apply
  n="LAOCOON_${k#ODYSSEUS_}"; [ -n "${!n:-}" ] || export "$n=${!k}"
done
if [ -z "${LAOCOON_SECRET:-}" ]; then        # private_data refuses a default secret: a random one, kept across runs
  [ -s "$HERE/.local-secret" ] || (umask 077; od -An -N24 -tx1 /dev/urandom | tr -d ' \n' > "$HERE/.local-secret")
  LAOCOON_SECRET="$(cat "$HERE/.local-secret")"
fi
export LAOCOON_SECRET
export LAOCOON_APP_KEY="${LAOCOON_APP_KEY:-lcn-demo-key}"
export LAOCOON_CONSOLE_TOKEN="${LAOCOON_CONSOLE_TOKEN:-change-me-console}"
export LAOCOON_POLICY="$HERE/policies/eclass.yaml"
# ② Siren Guard: optional. Backend jev (default when a key is given) | openai | hf | off. Empty values mean
# "the backend's own default" (model, base URL, timeout); every eClass/proxy process below inherits these.
export LAOCOON_GUARD_BACKEND="${LAOCOON_GUARD_BACKEND:-}" \
       LAOCOON_GUARD_MODEL="${LAOCOON_GUARD_MODEL:-${GUARD_MODEL:-}}" \
       LAOCOON_GUARD_BASE_URL="${LAOCOON_GUARD_BASE_URL:-}" \
       LAOCOON_GUARD_API_KEY="${LAOCOON_GUARD_API_KEY:-${TYPESAFE_API_KEY:-}}" \
       LAOCOON_GUARD_TIMEOUT="${LAOCOON_GUARD_TIMEOUT:-}" \
       LAOCOON_GUARD_LABELS="${LAOCOON_GUARD_LABELS:-}" \
       LAOCOON_GUARD_POINTS="${LAOCOON_GUARD_POINTS:-}"
GUARD_SHOW="${LAOCOON_GUARD_BACKEND:-$([ -n "$LAOCOON_GUARD_API_KEY" ] && echo jev || echo off)}"
[ "$GUARD_SHOW" = off ] || GUARD_SHOW="$GUARD_SHOW (${LAOCOON_GUARD_MODEL:-default model})"
GEMINI_OPENAI="https://generativelanguage.googleapis.com/v1beta/openai"

if [ "${1:-}" = "--mock" ]; then
  ( cd "$HERE" && exec "$VENV/bin/python" -m eval.mockllm --port "$PORT_MOCK" ) > "$RUN/mock.log" 2>&1 < /dev/null &
  echo $! > "$RUN/mock.pid"
  export LLM_PROVIDER=openai LLM_BASE_URL=http://127.0.0.1:$PORT_MOCK/v1 LLM_API_KEY=mock LLM_MODEL=mock-compromised
  UP_URL=http://127.0.0.1:$PORT_MOCK/v1 UP_KEY=mock UP_MODEL=mock-compromised
  sleep 1
else
  if [ "${LLM_PROVIDER:-gemini}" = "openai" ]; then
    UP_URL="${LLM_BASE_URL}" UP_KEY="${LLM_API_KEY:-}" UP_MODEL="${LLM_MODEL}"
  else
    UP_URL="$GEMINI_OPENAI" UP_KEY="${AI_STUDIO_API_KEY:-}" UP_MODEL="${GEMINI_MODEL:-gemini-3.5-flash-lite}"
  fi
  if [ -z "$UP_KEY" ] || [ "$UP_KEY" = "your-key-here" ]; then
    echo "No API key: put AI_STUDIO_API_KEY in $HERE/.env, or run with --mock for the offline demo." >&2
    exit 1
  fi
fi

start_eclass() {   # name dir port db extra-env...
  local name=$1 dir=$2 port=$3 db=$4; shift 4
  local common=(DB_PATH="$db" SHOW_TOOL_CALLS="${SHOW_TOOL_CALLS:-false}"
                SECRET_KEY="${SECRET_KEY:-change-me-hackathon}")
  ( cd "$dir" && env "$@" "${common[@]}" "$VENV/bin/python" -m app.seed --reset >/dev/null )
  ( cd "$dir" && exec env "$@" "${common[@]}" "$VENV/bin/gunicorn" app.app:app --bind "$BIND_HOST:$port" \
      --workers 2 --threads 4 --timeout 180 ) > "$RUN/$name.log" 2>&1 < /dev/null &
  echo $! > "$RUN/$name.pid"
}

rm -f "$DATA"/laocoon*.db*
# the proxy + the ORIGINAL eClass, configured only through the environment
start_eclass original "$ORIG" "$PORT_ORIG" "$DATA/eclass-original.db" \
  LLM_PROVIDER=openai LLM_BASE_URL="http://127.0.0.1:$PORT_PROXY/v1" LLM_API_KEY="$LAOCOON_APP_KEY" LLM_MODEL="$UP_MODEL"
sleep 2
( cd "$HERE" && exec env LAOCOON_DB="$DATA/laocoon-proxy.db" LAOCOON_ECLASS_DB="$DATA/eclass-original.db" \
    LAOCOON_IDENTITY=system_prompt LAOCOON_UPSTREAM_BASE_URL="$UP_URL" LAOCOON_UPSTREAM_API_KEY="$UP_KEY" \
    LAOCOON_UPSTREAM_MODEL="$UP_MODEL" \
    "$VENV/bin/gunicorn" laocoon.proxy:app --bind "$BIND_HOST:$PORT_PROXY" --workers 2 --threads 4 --timeout 180 ) \
    > "$RUN/proxy.log" 2>&1 < /dev/null &
echo $! > "$RUN/proxy.pid"
sleep 2
echo
cat <<EOF
  ORIGINAL eClass via proxy  http://localhost:$PORT_ORIG     (git status clean, only env changed)
  proxy console              http://localhost:$PORT_PROXY/laocoon?token=$LAOCOON_CONSOLE_TOKEN
  LLM upstream               $UP_URL ($UP_MODEL)
  guard classifier           $GUARD_SHOW
  logs: $RUN/*.log      stop: scripts/run_local.sh stop
  admin login (local only):  admin / Adm1n!Athena#2026
EOF

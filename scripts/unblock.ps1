# unblock.ps1 - remove the Mark-of-the-Web (Zone.Identifier ADS) from a file.
#
# The browser attaches Zone.Identifier (ZoneId=3) to every download. That single
# NTFS alternate data stream is what makes SmartScreen show "Windows protected
# your PC" and what makes Defender/AMSI treat the file as untrusted. Clearing it
# is the same thing Explorer's "Unblock" checkbox does.
#
# Usage:
#   powershell -File scripts\unblock.ps1 -Path C:\Users\Public\lab\loader.exe
#
param(
    [Parameter(Mandatory = $true)][string]$Path
)

$ErrorActionPreference = "Stop"
$full = (Resolve-Path -LiteralPath $Path).Path

Unblock-File -Path $full -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $full -Stream Zone.Identifier -Force -ErrorAction SilentlyContinue

$still = Get-Item -LiteralPath $full -Stream Zone.Identifier -ErrorAction SilentlyContinue
if ($still) {
    Write-Host "[-] Zone.Identifier still present on $full"
    exit 1
}
Write-Host "[+] MOTW cleared (no Zone.Identifier): $full"

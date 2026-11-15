//go:build windows

package identity

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type dataBlob struct {
	Size uint32
	Data *byte
}

var crypt32 = windows.NewLazySystemDLL("crypt32.dll")
var protect = crypt32.NewProc("CryptProtectData")
var unprotect = crypt32.NewProc("CryptUnprotectData")

func crypt(data []byte, encrypt bool) ([]byte, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return nil, errors.New("invalid DPAPI input size")
	}
	in := dataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out dataBlob
	proc := unprotect
	if encrypt {
		proc = protect
	}
	// CRYPTPROTECT_UI_FORBIDDEN, current-user scope. No machine-wide decryption.
	result, _, _ := proc.Call(uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	runtime.KeepAlive(data)
	if result == 0 {
		return nil, errors.New("DPAPI protection failed for current Windows account")
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(out.Data))))
	if out.Size > 1<<20 || out.Data == nil {
		return nil, errors.New("invalid DPAPI response")
	}
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}

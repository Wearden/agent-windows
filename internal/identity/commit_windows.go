//go:build windows

package identity

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func commitNewIdentity(from, to string) error {
	f, err := syscall.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	t, err := syscall.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	// MOVEFILE_WRITE_THROUGH without REPLACE_EXISTING preserves any existing identity.
	ok, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("MoveFileExW").Call(uintptr(unsafe.Pointer(f)), uintptr(unsafe.Pointer(t)), 8)
	if ok == 0 {
		return errors.New("cannot commit new identity without overwrite; encrypted temporary file retained")
	}
	return nil
}

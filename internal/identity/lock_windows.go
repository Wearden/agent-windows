//go:build windows

package identity

import (
	"errors"
	"syscall"
)

// Lock keeps a no-sharing Windows handle open, so a crash releases the lock.
func Lock(path string) (func(), error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, errors.New("cannot lock spool; another agent may own it")
	}
	return func() { syscall.CloseHandle(h) }, nil
}

//go:build windows

package actions

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

func TrustedServiceExecutable(path string) error { return trustedExecutable(path) }
func TrustedSystemState(path string) error       { return trustedState(path) }

func TrustedServicePath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil || !filepath.IsAbs(path) || strings.HasPrefix(abs, `\\`) {
		return errors.New("service state must be a fixed local absolute path")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || !strings.EqualFold(resolved, abs) {
		return errors.New("service state path must not traverse links")
	}
	info, err := os.Lstat(abs)
	if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
		return errors.New("service state must be a regular file or directory")
	}
	return trustedACL(abs, map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}, 0xffffffff)
}

// ProtectServicePath is called only by the explicit confirmed installer on its
// fixed ProgramData files. Interactive user SID access/ownership is not retained.
func ProtectServicePath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil || !filepath.IsAbs(path) || strings.HasPrefix(abs, `\\`) {
		return errors.New("invalid local service path")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || !strings.EqualFold(resolved, abs) {
		return errors.New("service path must not traverse links")
	}
	sddl, err := syscall.UTF16PtrFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	var descriptor uintptr
	ok, _, _ := parseSecurity.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 || descriptor == 0 {
		return errors.New("cannot construct service state ACL")
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	var present, defaulted uint32
	var acl uintptr
	ok, _, _ = getDACL.Call(descriptor, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&acl)), uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 || present == 0 || acl == 0 {
		return errors.New("service state DACL is invalid")
	}
	owner, err := syscall.StringToSid("S-1-5-32-544")
	if err != nil {
		return err
	}
	p, err := syscall.UTF16PtrFromString(abs)
	if err != nil {
		return err
	}
	status, _, _ := setSecurity.Call(uintptr(unsafe.Pointer(p)), 1, 0x80000005, uintptr(unsafe.Pointer(owner)), 0, acl, 0)
	if status != 0 {
		return errors.New("cannot assign Administrators ownership and SYSTEM-private service ACL; run elevated")
	}
	return TrustedServicePath(abs)
}

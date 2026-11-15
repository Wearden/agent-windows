//go:build windows

package actions

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var kernel = windows.NewLazySystemDLL("kernel32.dll")
var advapi = windows.NewLazySystemDLL("advapi32.dll")
var moveFile = kernel.NewProc("MoveFileExW")
var parseSecurity = advapi.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
var getDACL = advapi.NewProc("GetSecurityDescriptorDacl")
var setSecurity = advapi.NewProc("SetNamedSecurityInfoW")

func commit(from, to string, replace bool) error {
	f, err := syscall.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	t, err := syscall.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	flags := uintptr(8)
	if replace {
		flags |= 1
	}
	ok, _, _ := moveFile.Call(uintptr(unsafe.Pointer(f)), uintptr(unsafe.Pointer(t)), flags)
	if ok == 0 {
		return errors.New("cannot commit encrypted state atomically; temporary file retained")
	}
	return nil
}

func privateDirectory(path string) error {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return errors.New("cannot identify account for private task ACL")
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return errors.New("cannot identify account for private task ACL")
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return errors.New("cannot encode private task ACL principal")
	}
	sddl, err := syscall.UTF16PtrFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		return errors.New("cannot encode private task ACL")
	}
	var descriptor uintptr
	ok, _, _ := parseSecurity.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 || descriptor == 0 {
		return errors.New("cannot create private task ACL")
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	var present, defaulted uint32
	var acl uintptr
	ok, _, _ = getDACL.Call(descriptor, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&acl)), uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 || present == 0 || acl == 0 {
		return errors.New("private task ACL is missing")
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	status, _, _ := setSecurity.Call(uintptr(unsafe.Pointer(p)), 1, 0x80000004, 0, 0, acl, 0)
	if status != 0 {
		return errors.New("cannot apply private NTFS task directory ACL")
	}
	return nil
}

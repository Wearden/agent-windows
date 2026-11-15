//go:build windows

package actions

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var processInJob = kernel.NewProc("IsProcessInJob")
var namedSecurity = advapi.NewProc("GetNamedSecurityInfoW")
var aclInformation = advapi.NewProc("GetAclInformation")
var getACE = advapi.NewProc("GetAce")
var getTickCount = kernel.NewProc("GetTickCount64")

func uptimeMillis() uint64 {
	low, high, _ := getTickCount.Call()
	if strconv.IntSize == 32 {
		return uint64(low) | uint64(high)<<32
	}
	return uint64(low)
}

func lockTask(ctx context.Context, root, id string) (func(), error) {
	if !safeIdentifier(id) {
		return nil, errors.New("invalid task lock scope")
	}
	p, err := syscall.UTF16PtrFromString(filepath.Join(root, "watchdogs", id+".lock"))
	if err != nil {
		return nil, err
	}
	for {
		h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
		if err == nil {
			return func() { syscall.CloseHandle(h) }, nil
		}
		if err != syscall.Errno(32) && err != syscall.Errno(33) {
			return nil, errors.New("cannot open private task lock")
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func helperAlive(pid int) error {
	h, err := syscall.OpenProcess(0x1000, false, uint32(pid))
	if err != nil {
		return errors.New("independent recovery helper is unavailable")
	}
	defer syscall.CloseHandle(h)
	var inJob uint32
	ok, _, _ := processInJob.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&inJob)))
	if ok == 0 || inJob != 0 {
		return errors.New("independent recovery helper must be outside all Windows jobs")
	}
	var exit uint32
	if syscall.GetExitCodeProcess(h, &exit) != nil || exit != 259 {
		return errors.New("independent recovery helper has exited")
	}
	return nil
}

func startHelper(executable, root, id, nonce string) (int, error) {
	command := exec.Command(executable, "__watchdog", "--root", root, "--task", id, "--nonce", nonce)
	command.Dir = filepath.Dir(executable)
	command.Env = []string{}
	// Detached console and process group; fail closed if the containing job forbids breakaway.
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, NoInheritHandles: true, CreationFlags: 0x00000008 | 0x00000200 | 0x01000000}
	if err := command.Start(); err != nil {
		return 0, errors.New("cannot start job-independent recovery helper; no mutations authorized")
	}
	pid := command.Process.Pid
	if err := helperAlive(pid); err != nil {
		command.Process.Release()
		return 0, err
	}
	if err := command.Process.Release(); err != nil {
		return 0, errors.New("cannot release recovery helper process handle")
	}
	return pid, nil
}

func trustedACL(path string, allowed map[string]bool, writeMask uint32) error {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var owner *syscall.SID
	var acl, descriptor uintptr
	status, _, _ := namedSecurity.Call(uintptr(unsafe.Pointer(p)), 1, 1|4, uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&acl)), 0, uintptr(unsafe.Pointer(&descriptor)))
	if status != 0 || descriptor == 0 {
		return errors.New("cannot inspect trusted executable/state ACL")
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	if owner == nil || acl == 0 {
		return errors.New("trusted executable/state requires an owner and non-null DACL")
	}
	ownerText, err := owner.String()
	if err != nil || !allowed[ownerText] {
		return errors.New("executable/state owner is not a trusted principal")
	}
	var info struct{ Count, Used, Free uint32 }
	ok, _, _ := aclInformation.Call(acl, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), 2)
	if ok == 0 || info.Count > 4096 {
		return errors.New("invalid executable/state ACL")
	}
	for i := uint32(0); i < info.Count; i++ {
		var ace uintptr
		ok, _, _ = getACE.Call(acl, uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if ok == 0 || ace == 0 {
			return errors.New("cannot inspect executable/state ACE")
		}
		header := (*struct {
			Type, Flags byte
			Size        uint16
		})(unsafe.Pointer(ace))
		if header.Type == 1 {
			continue
		}
		if header.Type != 0 || header.Size < 16 {
			return errors.New("unsupported executable/state ACE layout")
		}
		mask := *(*uint32)(unsafe.Pointer(ace + 4))
		// INHERIT_ONLY entries do not grant access to this object.
		if header.Flags&8 != 0 || mask&writeMask == 0 {
			continue
		}
		principal, err := (*syscall.SID)(unsafe.Pointer(ace + 8)).String()
		if err != nil || !allowed[principal] {
			return errors.New("executable/state is writable by an untrusted principal")
		}
	}
	return nil
}

func trustedExecutable(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil || strings.HasPrefix(abs, `\\`) {
		return errors.New("recovery executable must be installed on a local volume")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || !strings.EqualFold(resolved, abs) {
		return errors.New("recovery executable path must not traverse links")
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("recovery executable must be a regular installed file")
	}
	trusted := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}
	if sid, _, _, err := syscall.LookupSID("", `NT SERVICE\TrustedInstaller`); err == nil {
		if text, e := sid.String(); e == nil {
			trusted[text] = true
		}
	}
	const fileWrites = uint32(0x10000000 | 0x40000000 | 0x000d0000 | 0x00000116)
	if err = trustedACL(abs, trusted, fileWrites); err != nil {
		return err
	}
	for dir := filepath.Dir(abs); ; dir = filepath.Dir(dir) {
		// Ancestors must not permit replacement/deletion or ACL takeover. Creating
		// unrelated children alone does not permit replacing the protected executable.
		if err = trustedACL(dir, trusted, 0x10000000|0x40000000|0x000d0000|0x40); err != nil {
			return err
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	return nil
}

func trustedState(root string) error {
	abs, err := filepath.Abs(root)
	if err != nil || !filepath.IsAbs(root) || strings.HasPrefix(abs, `\\`) {
		return errors.New("invalid local watchdog state root")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || !strings.EqualFold(resolved, abs) {
		return errors.New("watchdog state path must not traverse links")
	}
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return errors.New("cannot inspect watchdog account")
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return errors.New("cannot inspect watchdog account")
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return errors.New("cannot inspect watchdog account SID")
	}
	if sid != "S-1-5-18" {
		return errors.New("native task mutation and independent recovery require LocalSystem enrollment and daemon identity")
	}
	return trustedACL(root, map[string]bool{sid: true, "S-1-5-18": true, "S-1-5-32-544": true}, 0x10000000|0x40000000|0x000d0000|0x00000156)
}

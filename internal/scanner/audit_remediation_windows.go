//go:build windows

package scanner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var setAudit = advapi.NewProc("AuditSetSystemPolicy")
var adjustAuditPrivilege = advapi.NewProc("AdjustTokenPrivileges")

// Mutation/recovery callers already require LocalSystem. Use a temporary thread
// token so enabling SeSecurityPrivilege never changes the process token.
func withAuditPrivilege(action func() error) (err error) {
	runtime.LockOSThread()
	impersonating := false
	defer func() {
		if impersonating {
			if windows.RevertToSelf() != nil {
				fmt.Fprintln(os.Stderr, "fatal: cannot revert scoped audit privilege; independent recovery remains responsible for the pending task")
				os.Exit(1)
			}
		}
		runtime.UnlockOSThread()
	}()
	thread, err := windows.GetCurrentThread()
	if err != nil {
		return errors.New("cannot identify audit operation thread")
	}
	var existing windows.Token
	err = windows.OpenThreadToken(thread, windows.TOKEN_QUERY, true, &existing)
	if err == nil {
		return errors.Join(errors.New("audit operation refuses an existing impersonation context"), existing.Close())
	}
	if !errors.Is(err, windows.ERROR_NO_TOKEN) {
		return fmt.Errorf("cannot inspect audit thread context: %w", err)
	}
	if err = windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		return fmt.Errorf("cannot scope audit privilege: %w", err)
	}
	impersonating = true
	var token windows.Token
	if err = windows.OpenThreadToken(thread, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, true, &token); err != nil {
		return fmt.Errorf("cannot open scoped audit token: %w", err)
	}
	defer func() { err = errors.Join(err, token.Close()) }()
	name, err := syscall.UTF16PtrFromString("SeSecurityPrivilege")
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err = windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return fmt.Errorf("cannot resolve audit privilege: %w", err)
	}
	requested := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
	// The wrapper ignores ERROR_NOT_ALL_ASSIGNED on a successful BOOL return.
	// Inspect GetLastError from this exact call as well as the BOOL result.
	ok, _, last := adjustAuditPrivilege.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&requested)), 0, 0, 0)
	runtime.KeepAlive(requested)
	if ok == 0 || (last != nil && last != syscall.Errno(0)) {
		return fmt.Errorf("cannot enable scoped audit privilege: %v", last)
	}
	return action()
}

func snapshotAuditPolicy(plan RegistryPlan) (RegistrySnapshot, error) {
	snapshot := RegistrySnapshot{RuleID: plan.RuleID}
	err := withAuditPrivilege(func() error {
		value, err := auditPolicy(plan.Name)
		if err != nil {
			return err
		}
		flags, err := strconv.ParseUint(value, 10, 2)
		if err != nil {
			return errors.New("invalid native audit success/failure flags")
		}
		snapshot = RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: auditPolicySnapshotKind, Data: binary.LittleEndian.AppendUint32(nil, uint32(flags))}
		return nil
	})
	return snapshot, err
}

func replaceAuditPolicy(plan RegistryPlan, want, expected RegistrySnapshot) error {
	return withAuditPrivilege(func() error {
		current, err := auditPolicy(plan.Name)
		if err != nil {
			return err
		}
		if current != strconv.FormatUint(uint64(binary.LittleEndian.Uint32(expected.Data)), 10) {
			return errors.New("audit policy changed externally before write")
		}
		guid, err := auditSubcategory(plan.Name)
		if err != nil {
			return err
		}
		flags := binary.LittleEndian.Uint32(want.Data)
		setting := flags
		// Zero means UNCHANGED to the setter; NONE is the explicit disable operation.
		if setting == 0 {
			setting = 4
		}
		policy := auditInfo{Subcategory: guid, Settings: setting}
		ok, _, err := setAudit.Call(uintptr(unsafe.Pointer(&policy)), 1)
		runtime.KeepAlive(policy)
		if ok&0xff == 0 {
			return fmt.Errorf("native audit-policy write failed: %w", err)
		}
		after, err := auditPolicy(plan.Name)
		if err != nil {
			return err
		}
		if after != strconv.FormatUint(uint64(flags), 10) {
			return errors.New("native audit-policy recheck did not match requested success/failure flags")
		}
		return nil
	})
}

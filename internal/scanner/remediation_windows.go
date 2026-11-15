//go:build windows

package scanner

import (
	"context"
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

var setRegistry = advapi.NewProc("RegSetValueExW")
var deleteRegistry = advapi.NewProc("RegDeleteValueW")
var flushRegistry = advapi.NewProc("RegFlushKey")

func Snapshot(plan RegistryPlan) (RegistrySnapshot, error) {
	snapshot := RegistrySnapshot{RuleID: plan.RuleID}
	approved, err := Plan(plan.RuleID)
	if err != nil || approved != plan {
		return snapshot, errors.New("registry plan is not approved")
	}
	if plan.Provider == "password_policy" {
		return snapshotAccountPolicy(plan)
	}
	if plan.Provider == "audit_policy" {
		return snapshotAuditPolicy(plan)
	}
	if plan.Provider == "service" {
		return snapshotService(plan)
	}
	if plan.Provider == "user_right" {
		return snapshotUserRight(plan)
	}
	p, err := syscall.UTF16PtrFromString(plan.Path)
	if err != nil {
		return snapshot, errors.New("invalid compiled registry path")
	}
	n, err := syscall.UTF16PtrFromString(plan.Name)
	if err != nil {
		return snapshot, errors.New("invalid compiled registry name")
	}
	var key syscall.Handle
	if err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, p, 0, 0x0001|0x0100, &key); err != nil {
		return snapshot, err
	}
	defer syscall.RegCloseKey(key)
	var kind, size uint32
	err = syscall.RegQueryValueEx(key, n, nil, &kind, nil, &size)
	if err == syscall.ERROR_FILE_NOT_FOUND {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	if kind != snapshotKind(plan) || size > 65536 {
		return snapshot, errors.New("refusing to replace an unexpected registry type or size")
	}
	data := make([]byte, size+2)
	if err = syscall.RegQueryValueEx(key, n, nil, &kind, &data[0], &size); err != nil {
		return snapshot, err
	}
	if kind != snapshotKind(plan) || size > uint32(len(data)) {
		return snapshot, errors.New("registry type or size changed while reading")
	}
	snapshot = RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: kind, Data: data[:size]}
	if !ValidSnapshot(plan, snapshot) {
		return RegistrySnapshot{RuleID: plan.RuleID}, errors.New("registry snapshot has an unsupported type, size or string encoding")
	}
	return snapshot, nil
}

// Replace never creates/deletes a key. Expected-state checks detect policy drift;
// registry APIs do not provide a cross-process compare-and-swap transaction.
func Replace(plan RegistryPlan, want, expected RegistrySnapshot) error {
	return ReplaceContext(context.Background(), plan, want, expected)
}

func ReplaceContext(ctx context.Context, plan RegistryPlan, want, expected RegistrySnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !ValidSnapshot(plan, want) || !ValidSnapshot(plan, expected) {
		return errors.New("invalid registry snapshot")
	}
	current, err := Snapshot(plan)
	if err != nil {
		return err
	}
	if !SameSnapshot(current, expected) {
		return errors.New("registry value changed externally; refusing overwrite")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if plan.Provider == "password_policy" {
		return replaceAccountPolicy(plan, want, expected)
	}
	if plan.Provider == "audit_policy" {
		return replaceAuditPolicy(plan, want, expected)
	}
	if plan.Provider == "service" {
		return replaceService(ctx, plan, want, expected)
	}
	if plan.Provider == "user_right" {
		return replaceUserRight(ctx, plan, want, expected)
	}
	p, err := syscall.UTF16PtrFromString(plan.Path)
	if err != nil {
		return errors.New("invalid compiled registry path")
	}
	n, err := syscall.UTF16PtrFromString(plan.Name)
	if err != nil {
		return errors.New("invalid compiled registry name")
	}
	var key syscall.Handle
	if err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, p, 0, 0x0001|0x0002|0x0100, &key); err != nil {
		return err
	}
	defer syscall.RegCloseKey(key)
	var result uintptr
	if want.Exists {
		result, _, _ = setRegistry.Call(uintptr(key), uintptr(unsafe.Pointer(n)), 0, uintptr(want.Kind), uintptr(unsafe.Pointer(&want.Data[0])), uintptr(len(want.Data)))
		runtime.KeepAlive(want.Data)
	} else {
		result, _, _ = deleteRegistry.Call(uintptr(key), uintptr(unsafe.Pointer(n)))
	}
	if result != 0 && !(result == uintptr(syscall.ERROR_FILE_NOT_FOUND) && !want.Exists) {
		return syscall.Errno(result)
	}
	result, _, _ = flushRegistry.Call(uintptr(key))
	if result != 0 {
		return syscall.Errno(result)
	}
	after, err := Snapshot(plan)
	if err != nil {
		return err
	}
	if !SameSnapshot(after, want) {
		return errors.New("native registry recheck did not match requested state")
	}
	return nil
}

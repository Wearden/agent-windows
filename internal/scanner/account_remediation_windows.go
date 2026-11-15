//go:build windows

package scanner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var setModals = netapi.NewProc("NetUserModalsSet")

func localAccountPolicyHost() error {
	version := windows.RtlGetVersion()
	if version == nil || (version.ProductType != 1 && version.ProductType != 3) {
		return errors.New("account-policy writes require a workstation or non-DC server; domain policy is outside this local mutation scope")
	}
	return nil
}

func snapshotAccountPolicy(plan RegistryPlan) (RegistrySnapshot, error) {
	snapshot := RegistrySnapshot{RuleID: plan.RuleID}
	if err := localAccountPolicyHost(); err != nil {
		return snapshot, err
	}
	value, err := passwordPolicy(plan.Name)
	if err != nil {
		return snapshot, err
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return snapshot, errors.New("invalid native account-policy scalar")
	}
	return RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: accountPolicySnapshotKind, Data: binary.LittleEndian.AppendUint32(nil, uint32(parsed))}, nil
}

func replaceAccountPolicy(plan RegistryPlan, want, expected RegistrySnapshot) error {
	if err := localAccountPolicyHost(); err != nil {
		return err
	}
	value := binary.LittleEndian.Uint32(want.Data)
	var level uintptr
	switch plan.Name {
	case "min_length":
		level = 1001
	case "max_age_seconds":
		level = 1002
	case "min_age_seconds":
		level = 1003
	case "history_length":
		level = 1005
	case "lockout_duration_seconds", "lockout_window_seconds", "lockout_threshold":
		level = 3
	default:
		return errors.New("unknown compiled account-policy field")
	}
	var parameter uint32
	var status uintptr
	if level == 3 {
		var data *byte
		result, _, _ := getModals.Call(0, 3, uintptr(unsafe.Pointer(&data)))
		if result != 0 {
			return fmt.Errorf("lockout policy read failed with native status %d", result)
		}
		if data == nil {
			return errors.New("empty native lockout policy")
		}
		defer syscall.NetApiBufferFree(data)
		policy := *(*modals3)(unsafe.Pointer(data))
		var field *uint32
		switch plan.Name {
		case "lockout_duration_seconds":
			field = &policy.Duration
		case "lockout_window_seconds":
			field = &policy.Window
		case "lockout_threshold":
			field = &policy.Threshold
		}
		if *field != binary.LittleEndian.Uint32(expected.Data) {
			return errors.New("lockout policy changed externally before write")
		}
		*field = value
		// Level3 is the API's lockout group; retain the current unselected fields.
		status, _, _ = setModals.Call(0, level, uintptr(unsafe.Pointer(&policy)), uintptr(unsafe.Pointer(&parameter)))
		runtime.KeepAlive(policy)
	} else {
		status, _, _ = setModals.Call(0, level, uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&parameter)))
		runtime.KeepAlive(value)
	}
	if status != 0 {
		return fmt.Errorf("account-policy write failed with native status %d (field %d)", status, parameter)
	}
	after, err := snapshotAccountPolicy(plan)
	if err != nil {
		return err
	}
	if !SameSnapshot(after, want) {
		return errors.New("native account-policy recheck did not match requested state")
	}
	return nil
}

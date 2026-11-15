//go:build windows

package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"runtime"

	"golang.org/x/sys/windows"
)

func withSMBDriver(write bool, operation func(windows.Handle, windows.Handle) error) (err error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return errors.New("cannot open local service manager for SMB policy")
	}
	defer func() { err = errors.Join(err, windows.CloseServiceHandle(manager)) }()
	access := uint32(windows.SERVICE_QUERY_CONFIG)
	if write {
		access |= windows.SERVICE_CHANGE_CONFIG
	}
	open := func(name string) (windows.Handle, error) {
		wide, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return 0, err
		}
		handle, err := windows.OpenService(manager, wide, access)
		if err != nil {
			return 0, errors.New("required local SMB service configuration is unavailable")
		}
		return handle, nil
	}
	driver, err := open("mrxsmb10")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, windows.CloseServiceHandle(driver)) }()
	workstation, err := open("LanmanWorkstation")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, windows.CloseServiceHandle(workstation)) }()
	return operation(driver, workstation)
}

func smbDriverFromHandles(plan RegistryPlan, driver, workstation windows.Handle) (RegistrySnapshot, error) {
	read := func() (RegistrySnapshot, error) {
		d, err := readServicePolicyMetadata(driver, true, false)
		if err != nil {
			return RegistrySnapshot{}, err
		}
		w, err := readServicePolicyMetadata(workstation, false, true)
		if err != nil {
			return RegistrySnapshot{}, err
		}
		data := binary.LittleEndian.AppendUint32(nil, d.start)
		data = append(data, d.fingerprint[:]...)
		data = append(data, w.fingerprint[:]...)
		data = append(data, encodeSMBDependencies(w.dependencies)...)
		snapshot := RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: smbDriverSnapshotKind, Data: data}
		if !ValidSnapshot(plan, snapshot) {
			return RegistrySnapshot{}, errors.New("SMB policy snapshot is outside reviewed native bounds")
		}
		return snapshot, nil
	}
	before, err := read()
	if err != nil {
		return RegistrySnapshot{}, err
	}
	after, err := read()
	if err != nil || !SameSnapshot(before, after) {
		return RegistrySnapshot{}, errors.New("SMB configuration changed during observation")
	}
	return after, nil
}

func snapshotSMBDriver(plan RegistryPlan) (snapshot RegistrySnapshot, err error) {
	err = withSMBDriver(false, func(driver, workstation windows.Handle) error {
		var err error
		snapshot, err = smbDriverFromHandles(plan, driver, workstation)
		return err
	})
	return snapshot, err
}

// Configuration only: no StartService, ControlService or driver unload.
func replaceSMBDriver(ctx context.Context, plan RegistryPlan, want, expected RegistrySnapshot) error {
	wantOther, err := withoutSMB1Dependency(want.Data[68:])
	if err != nil {
		return err
	}
	expectedOther, err := withoutSMB1Dependency(expected.Data[68:])
	if err != nil || !bytes.Equal(wantOther, expectedOther) || !bytes.Equal(want.Data[4:68], expected.Data[4:68]) {
		return errors.New("SMB change may only alter driver startup and its Workstation dependency")
	}
	return withSMBDriver(true, func(driver, workstation windows.Handle) error {
		intermediate := expected
		ready := func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			current, err := smbDriverFromHandles(plan, driver, workstation)
			if err != nil || !SameSnapshot(current, intermediate) {
				return errors.New("SMB configuration drift detected before the next field update")
			}
			return nil
		}
		startup := func() error {
			if bytes.Equal(intermediate.Data[:4], want.Data[:4]) {
				return nil
			}
			if err := ready(); err != nil {
				return err
			}
			if windows.ChangeServiceConfig(driver, windows.SERVICE_NO_CHANGE, binary.LittleEndian.Uint32(want.Data), windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, nil, nil, nil) != nil {
				return errors.New("cannot change SMB driver startup configuration")
			}
			data := append([]byte(nil), intermediate.Data...)
			copy(data[:4], want.Data[:4])
			intermediate.Data = data
			return nil
		}
		dependencies := func() error {
			if bytes.Equal(intermediate.Data[68:], want.Data[68:]) {
				return nil
			}
			if err := ready(); err != nil {
				return err
			}
			words := make([]uint16, (len(want.Data)-68)/2)
			for i := range words {
				words[i] = binary.LittleEndian.Uint16(want.Data[68+i*2:])
			}
			if windows.ChangeServiceConfig(workstation, windows.SERVICE_NO_CHANGE, windows.SERVICE_NO_CHANGE, windows.SERVICE_NO_CHANGE, nil, nil, nil, &words[0], nil, nil, nil) != nil {
				return errors.New("cannot change the selected SMB Workstation dependency")
			}
			runtime.KeepAlive(words)
			data := append([]byte(nil), intermediate.Data[:68]...)
			intermediate.Data = append(data, want.Data[68:]...)
			return nil
		}
		// Remove the dependency before disabling; restore startup before adding it.
		steps := []func() error{dependencies, startup}
		if binary.LittleEndian.Uint32(want.Data) != windows.SERVICE_DISABLED {
			steps = []func() error{startup, dependencies}
		}
		for _, step := range steps {
			if err := step(); err != nil {
				return err
			}
		}
		if err := ready(); err != nil {
			return err
		}
		if !SameSnapshot(intermediate, want) {
			return errors.New("SMB policy update did not reach the requested configuration")
		}
		return nil
	})
}

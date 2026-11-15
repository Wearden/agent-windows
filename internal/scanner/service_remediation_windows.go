//go:build windows

package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

type serviceMetadata struct {
	start, delayed, kind uint32
	dependencies         []string
	fingerprint          [32]byte
}

func serviceConfigString(buffer []byte, pointer *uint16) ([]byte, error) {
	if pointer == nil {
		return nil, nil
	}
	base, address := uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(pointer))
	if address < base || address-base >= uintptr(len(buffer)) || (address-base)%2 != 0 {
		return nil, errors.New("service configuration string is outside the native buffer")
	}
	offset := int(address - base)
	for i := offset; i+1 < len(buffer); i += 2 {
		if binary.LittleEndian.Uint16(buffer[i:]) == 0 {
			return buffer[offset:i], nil
		}
	}
	return nil, errors.New("unterminated native service configuration string")
}

func withNativeService(plan RegistryPlan, write bool, operation func(windows.Handle, windows.Handle) error) (err error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return errors.New("cannot open local service manager")
	}
	defer func() {
		if e := windows.CloseServiceHandle(manager); e != nil && err == nil {
			err = errors.New("cannot close service manager handle")
		}
	}()
	name, err := windows.UTF16PtrFromString(plan.Name)
	if err != nil || !serviceNames[plan.Name] {
		return errors.New("unapproved service name")
	}
	access := uint32(windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS)
	if write {
		access |= windows.SERVICE_CHANGE_CONFIG | windows.SERVICE_START | windows.SERVICE_STOP
	}
	service, err := windows.OpenService(manager, name, access)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) && !write {
		return nil
	}
	if err != nil {
		return errors.New("cannot open the approved local service")
	}
	defer func() {
		if e := windows.CloseServiceHandle(service); e != nil && err == nil {
			err = errors.New("cannot close service handle")
		}
	}()
	return operation(manager, service)
}

func readServiceMetadata(service windows.Handle) (serviceMetadata, error) {
	return readServicePolicyMetadata(service, false, false)
}

func readServicePolicyMetadata(service windows.Handle, driver, mutableDependencies bool) (serviceMetadata, error) {
	var meta serviceMetadata
	var needed uint32
	err := windows.QueryServiceConfig(service, nil, 0, &needed)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || needed < uint32(unsafe.Sizeof(windows.QUERY_SERVICE_CONFIG{})) || needed > 65536 {
		return meta, errors.New("invalid native service configuration size")
	}
	buffer := make([]byte, needed)
	config := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buffer[0]))
	if windows.QueryServiceConfig(service, config, uint32(len(buffer)), &needed) != nil || needed > uint32(len(buffer)) {
		return meta, errors.New("cannot read service configuration")
	}
	meta.start, meta.kind = config.StartType, config.ServiceType
	if driver {
		if meta.start > windows.SERVICE_DISABLED || meta.kind != windows.SERVICE_FILE_SYSTEM_DRIVER {
			return meta, errors.New("SMB driver configuration is outside the reviewed filesystem-driver shape")
		}
	} else if meta.start < windows.SERVICE_AUTO_START || meta.start > windows.SERVICE_DISABLED || (meta.kind&^uint32(windows.SERVICE_INTERACTIVE_PROCESS) != windows.SERVICE_WIN32_OWN_PROCESS && meta.kind&^uint32(windows.SERVICE_INTERACTIVE_PROCESS) != windows.SERVICE_WIN32_SHARE_PROCESS) {
		return meta, errors.New("driver or unreviewed service configuration is outside this provider")
	}
	// Hash unmodified basic configuration, never store/emit its text. A service
	// reconfigured to another executable/account must not be restarted by rollback.
	hash := sha256.New()
	for _, value := range []uint32{meta.kind, config.ErrorControl, config.TagId} {
		hash.Write(binary.LittleEndian.AppendUint32(nil, value))
	}
	addText := func(value []byte) {
		hash.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(value))))
		hash.Write(value)
	}
	for _, pointer := range []*uint16{config.BinaryPathName, config.LoadOrderGroup, config.ServiceStartName, config.DisplayName} {
		value, err := serviceConfigString(buffer, pointer)
		if err != nil {
			return meta, err
		}
		addText(value)
	}
	if config.Dependencies != nil {
		base, pointer := uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(config.Dependencies))
		if pointer < base || pointer-base >= uintptr(len(buffer)) || (pointer-base)%2 != 0 {
			return meta, errors.New("service dependency pointer is outside the native buffer")
		}
		offset := int(pointer - base)
		words := unsafe.Slice((*uint16)(unsafe.Pointer(&buffer[offset])), (len(buffer)-offset)/2)
		first, terminated := 0, false
		for i, word := range words {
			if word != 0 {
				if i-first >= 256 {
					return meta, errors.New("service dependency name exceeds reviewed bounds")
				}
				continue
			}
			if i == first {
				terminated = true
				break
			}
			if len(meta.dependencies) >= 32 {
				return meta, errors.New("service dependency count exceeds32")
			}
			name := windows.UTF16ToString(words[first:i])
			if !slices.Equal(utf16.Encode([]rune(name)), words[first:i]) {
				return meta, errors.New("invalid UTF-16 service dependency name")
			}
			meta.dependencies = append(meta.dependencies, name)
			if !mutableDependencies {
				addText(buffer[offset+first*2 : offset+i*2])
			}
			first = i + 1
		}
		if !terminated {
			return meta, errors.New("unterminated native service dependency list")
		}
	}
	if !mutableDependencies {
		hash.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(meta.dependencies))))
	}
	copy(meta.fingerprint[:], hash.Sum(nil))
	runtime.KeepAlive(buffer)
	if driver {
		return meta, nil
	}
	var delayed windows.SERVICE_DELAYED_AUTO_START_INFO
	if windows.QueryServiceConfig2(service, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, (*byte)(unsafe.Pointer(&delayed)), uint32(unsafe.Sizeof(delayed)), &needed) != nil || delayed.IsDelayedAutoStartUp > 1 {
		return meta, errors.New("cannot read delayed service startup flag")
	}
	meta.delayed = delayed.IsDelayedAutoStartUp
	return meta, nil
}

func serviceRuntime(service windows.Handle) (uint32, error) {
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed) != nil {
		return 0, errors.New("cannot read native service runtime status")
	}
	return status.CurrentState, nil
}

func stableServiceRuntime(service windows.Handle, deadline time.Time) (uint32, error) {
	for {
		if !time.Now().Before(deadline) {
			return 0, errors.New("service transition did not reach a stable state within the observation deadline")
		}
		state, err := serviceRuntime(service)
		if err != nil {
			return 0, err
		}
		switch state {
		case windows.SERVICE_RUNNING, windows.SERVICE_STOPPED:
			return state, nil
		case windows.SERVICE_START_PENDING, windows.SERVICE_STOP_PENDING:
			time.Sleep(100 * time.Millisecond)
		default:
			return 0, errors.New("paused or unreviewed service runtime state requires manual review")
		}
	}
}

func serviceSnapshotFromHandle(plan RegistryPlan, service windows.Handle, deadline time.Time) (RegistrySnapshot, error) {
	meta, err := readServiceMetadata(service)
	if err != nil {
		return RegistrySnapshot{}, err
	}
	state, err := stableServiceRuntime(service, deadline)
	if err != nil {
		return RegistrySnapshot{}, err
	}
	after, err := readServiceMetadata(service)
	if err != nil || meta.start != after.start || meta.delayed != after.delayed || meta.fingerprint != after.fingerprint {
		return RegistrySnapshot{}, errors.New("service configuration changed during observation")
	}
	data := binary.LittleEndian.AppendUint32(nil, meta.start)
	data = binary.LittleEndian.AppendUint32(data, state)
	data = binary.LittleEndian.AppendUint32(data, meta.delayed)
	data = append(data, meta.fingerprint[:]...)
	return RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: serviceSnapshotKind, Data: data}, nil
}

func snapshotService(plan RegistryPlan) (snapshot RegistrySnapshot, err error) {
	snapshot.RuleID = plan.RuleID
	err = withNativeService(plan, false, func(manager windows.Handle, service windows.Handle) error {
		var e error
		snapshot, e = serviceSnapshotFromHandle(plan, service, time.Now().Add(6*time.Second))
		if e != nil {
			return e
		}
		if binary.LittleEndian.Uint32(snapshot.Data[4:]) == windows.SERVICE_RUNNING {
			meta, e := readServiceMetadata(service)
			if e != nil {
				return e
			}
			return requireRunningDependencies(manager, meta.dependencies)
		}
		return nil
	})
	return snapshot, err
}

func requireRunningDependencies(manager windows.Handle, dependencies []string) error {
	for _, name := range dependencies {
		if strings.HasPrefix(name, "+") {
			return errors.New("service dependency groups require manual restoration review")
		}
		wide, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return errors.New("invalid native dependency name")
		}
		dependency, err := windows.OpenService(manager, wide, windows.SERVICE_QUERY_STATUS)
		if err != nil {
			return errors.New("cannot inspect service dependency before restart")
		}
		state, queryErr := serviceRuntime(dependency)
		closeErr := windows.CloseServiceHandle(dependency)
		if queryErr != nil || closeErr != nil || state != windows.SERVICE_RUNNING {
			return errors.New("service dependency is unavailable or not running; refusing implicit dependency startup")
		}
	}
	return nil
}

func replaceService(ctx context.Context, plan RegistryPlan, want, expected RegistrySnapshot) error {
	if !want.Exists || !expected.Exists {
		return errors.New("service creation and deletion are outside the compiled mutation scope")
	}
	return withNativeService(plan, true, func(manager, service windows.Handle) error {
		deadline := time.Now().Add(10 * time.Second)
		if authorized, ok := ctx.Deadline(); ok && authorized.Before(deadline) {
			deadline = authorized
		}
		ready := func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !time.Now().Before(deadline) {
				return errors.New("service mutation authorization or observation deadline exceeded")
			}
			return nil
		}
		current, err := serviceSnapshotFromHandle(plan, service, deadline)
		if err != nil {
			return err
		}
		if !SameSnapshot(current, expected) {
			return errors.New("service state changed externally before mutation")
		}
		start, state, delayed := binary.LittleEndian.Uint32(want.Data), binary.LittleEndian.Uint32(want.Data[4:]), binary.LittleEndian.Uint32(want.Data[8:])
		transitionStart := start
		if start == windows.SERVICE_DISABLED && state == windows.SERVICE_RUNNING {
			transitionStart = windows.SERVICE_DEMAND_START
		}
		if binary.LittleEndian.Uint32(current.Data) != transitionStart {
			if err := ready(); err != nil {
				return err
			}
			if windows.ChangeServiceConfig(service, windows.SERVICE_NO_CHANGE, transitionStart, windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, nil, nil, nil) != nil {
				return errors.New("cannot change compiled service startup policy")
			}
		}
		if binary.LittleEndian.Uint32(current.Data[8:]) != delayed {
			if err := ready(); err != nil {
				return err
			}
			flag := windows.SERVICE_DELAYED_AUTO_START_INFO{IsDelayedAutoStartUp: delayed}
			if windows.ChangeServiceConfig2(service, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, (*byte)(unsafe.Pointer(&flag))) != nil {
				return errors.New("cannot restore compiled delayed startup flag")
			}
		}
		live, err := stableServiceRuntime(service, deadline)
		if err != nil {
			return err
		}
		if live != state {
			if err := ready(); err != nil {
				return err
			}
			if state == windows.SERVICE_STOPPED {
				var status windows.SERVICE_STATUS
				if windows.ControlService(service, windows.SERVICE_CONTROL_STOP, &status) != nil {
					return errors.New("cannot stop service; dependent services are never forcibly stopped")
				}
			} else {
				meta, err := readServiceMetadata(service)
				if err != nil {
					return err
				}
				if err := requireRunningDependencies(manager, meta.dependencies); err != nil {
					return err
				}
				if err := ready(); err != nil {
					return err
				}
				if windows.StartService(service, 0, nil) != nil {
					return errors.New("cannot restore service running state")
				}
			}
			live, err = stableServiceRuntime(service, deadline)
			if err != nil || live != state {
				return errors.New("service runtime transition did not reach the saved state")
			}
		}
		if transitionStart != start {
			if err := ready(); err != nil {
				return err
			}
			if windows.ChangeServiceConfig(service, windows.SERVICE_NO_CHANGE, start, windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, nil, nil, nil) != nil {
				return errors.New("cannot restore disabled startup after restoring running service")
			}
		}
		after, err := serviceSnapshotFromHandle(plan, service, deadline)
		if err != nil || !SameSnapshot(after, want) {
			return errors.New("native service recheck differs from the exact requested state")
		}
		return nil
	})
}

//go:build windows

package scanner

import (
	"encoding/binary"
	"errors"
	"syscall"
	"unsafe"

	"github.com/Wearden/proto/wire"
	"golang.org/x/sys/windows"
)

func lsaTargetMode() (uint32, error) {
	v := windows.RtlGetVersion()
	if v == nil || v.MajorVersion != 10 {
		return 0, errors.New("LSA protection requires reviewed Windows version metadata")
	}
	if v.ProductType == 1 && v.BuildNumber >= 22621 {
		return 2, nil // Supported protected-process configuration without UEFI lock.
	}
	return 1, nil
}

func lsaProtectionValue(rule Rule) (string, error) {
	kind, data, err := registryRaw(rule.Path, rule.Name)
	if err == syscall.ERROR_FILE_NOT_FOUND || err == syscall.ERROR_PATH_NOT_FOUND {
		return "Disabled", nil
	}
	if err != nil {
		return "", err
	}
	if kind != syscall.REG_DWORD || len(data) != 4 {
		return "", errors.New("RunAsPPL must be a DWORD policy value")
	}
	value := binary.LittleEndian.Uint32(data)
	switch value {
	case 0:
		return "Disabled", nil
	case 1:
		return "Enabled", nil
	case 2:
		mode, err := lsaTargetMode()
		if err != nil {
			return "", err
		}
		if mode == 2 {
			return "Enabled", nil
		}
		return "Disabled", nil
	default:
		return "", errors.New("unreviewed RunAsPPL policy value")
	}
}

func lsaSecureBootEnabled() (bool, error) {
	var info struct{ Enabled, Capable byte }
	var size uint32
	if err := windows.NtQuerySystemInformation(windows.SystemSecureBootInformation, unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), &size); err != nil {
		return false, errors.New("cannot establish kernel Secure Boot metadata for reversible LSA configuration")
	}
	if size != uint32(unsafe.Sizeof(info)) || info.Enabled > 1 || info.Capable > 1 || info.Enabled > info.Capable {
		return false, errors.New("kernel Secure Boot metadata has an unreviewed shape")
	}
	return info.Enabled == 1, nil
}

func lsaApplyPrecondition(plan RegistryPlan) error {
	current, err := Snapshot(plan)
	if err != nil {
		return err
	}
	if SnapshotStatus(plan, current) == wire.Pass || plan.Desired == 2 {
		return nil
	}
	enabled, err := lsaSecureBootEnabled()
	if err != nil {
		return err
	}
	if enabled {
		return errors.New("this Windows release requires firmware-locking RunAsPPL mode under Secure Boot; automated reversible apply is refused")
	}
	return nil
}

// Registry restoration must not pretend that it can undo a firmware lock if
// Secure Boot changed after the original task. No firmware write API is invoked.
func lsaRegistryWritePrecondition(want, expected RegistrySnapshot) error {
	mode := func(snapshot RegistrySnapshot) uint32 {
		if !snapshot.Exists {
			return 0
		}
		return binary.LittleEndian.Uint32(snapshot.Data)
	}
	if SameSnapshot(want, expected) || (mode(want) != 1 && mode(expected) != 1) {
		return nil
	}
	enabled, err := lsaSecureBootEnabled()
	if err != nil {
		return err
	}
	if enabled {
		return errors.New("RunAsPPL transition involving mode1 under Secure Boot requires manual firmware review; registry-only restoration is insufficient")
	}
	return nil
}

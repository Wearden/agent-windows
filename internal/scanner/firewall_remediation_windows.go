//go:build windows

package scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

// INetFwPolicy2's SDK vtable inherits IDispatch. Only the selected scalar
// getters/setters below are called; no rules, groups, interfaces or defaults reset.
type firewallPolicyVtbl struct {
	unknownVtbl
	dispatch                                         [4]uintptr
	currentProfiles, getEnabled, putEnabled          uintptr
	unusedProfileSettings                            [8]uintptr
	unusedCollections                                [2]uintptr
	unusedRuleMethods                                [3]uintptr
	getInbound, putInbound, getOutbound, putOutbound uintptr
	unusedRuleGroup, getModifyState                  uintptr
}

type firewallPolicy struct{ Vtbl *firewallPolicyVtbl }

func withFirewallPolicy(operation func(*firewallPolicy) error) error {
	if err := initializeWMI(); err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result, _, _ := initializeCOM.Call(0, 0)
	if err := hresult("CoInitializeEx", result); err != nil {
		return err
	}
	defer uninitializeCOM.Call()
	securityOnce.Do(func() {
		result, _, _ := initializeSecurity.Call(0, ^uintptr(0), 0, 0, 0, 3, 0, 0, 0)
		if uint32(result) != 0x80010119 {
			securityError = hresult("CoInitializeSecurity", result)
		}
	})
	if securityError != nil {
		return securityError
	}
	clsid := syscall.GUID{Data1: 0xe2b3c97f, Data2: 0x6ae1, Data3: 0x41ac, Data4: [8]byte{0x81, 0x7a, 0xf6, 0xf9, 0x21, 0x66, 0xd7, 0xdd}}
	iid := syscall.GUID{Data1: 0x98325047, Data2: 0xc671, Data3: 0x4174, Data4: [8]byte{0x8d, 0x81, 0xde, 0xfc, 0xd3, 0xf0, 0x31, 0x86}}
	var policy *firewallPolicy
	result, _, _ = createCOM.Call(uintptr(unsafe.Pointer(&clsid)), 0, 1, uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&policy)))
	if err := hresult("CoCreateInstance(INetFwPolicy2)", result); err != nil {
		return err
	}
	if policy == nil {
		return errors.New("local firewall policy interface is unavailable")
	}
	defer releaseCOM(unsafe.Pointer(policy))
	return operation(policy)
}

func firewallProfile(plan RegistryPlan) (uint32, string, error) {
	check, ok := firewallChecks[plan.Name]
	profile := map[string]uint32{"Domain": 1, "Private": 2, "Public": 4}[check.Profile]
	if !ok || profile == 0 || plan.Provider != "firewall" || (check.Property != "Enabled" && check.Property != "DefaultInboundAction") {
		return 0, "", errors.New("firewall property is outside the compiled write scope")
	}
	return profile, check.Property, nil
}

func readFirewallScalar(policy *firewallPolicy, plan RegistryPlan) (uint32, error) {
	profile, property, err := firewallProfile(plan)
	if err != nil {
		return 0, err
	}
	if property == "Enabled" {
		var enabled int16
		result, _, _ := syscall.SyscallN(policy.Vtbl.getEnabled, uintptr(unsafe.Pointer(policy)), uintptr(profile), uintptr(unsafe.Pointer(&enabled)))
		if err := hresult("INetFwPolicy2.get_FirewallEnabled", result); err != nil {
			return 0, err
		}
		if enabled == -1 {
			return 1, nil
		}
		if enabled != 0 {
			return 0, errors.New("invalid native firewall Boolean")
		}
		return 0, nil
	}
	var action int32
	result, _, _ := syscall.SyscallN(policy.Vtbl.getInbound, uintptr(unsafe.Pointer(policy)), uintptr(profile), uintptr(unsafe.Pointer(&action)))
	if err := hresult("INetFwPolicy2.get_DefaultInboundAction", result); err != nil {
		return 0, err
	}
	if action != 0 && action != 1 {
		return 0, errors.New("invalid native firewall default action")
	}
	return uint32(action), nil
}

func ApplyPrecondition(plan RegistryPlan) error {
	approved, err := Plan(plan.RuleID)
	if err != nil || approved != plan {
		return errors.New("native apply plan is not approved")
	}
	if plan.Provider != "firewall" {
		return nil
	}
	return withFirewallPolicy(func(policy *firewallPolicy) error {
		var state int32
		result, _, _ := syscall.SyscallN(policy.Vtbl.getModifyState, uintptr(unsafe.Pointer(policy)), uintptr(unsafe.Pointer(&state)))
		if err := hresult("INetFwPolicy2.get_LocalPolicyModifyState", result); err != nil {
			return err
		}
		if state != 0 {
			return errors.New("current firewall profile reports overridden or blocked local policy modification")
		}
		return nil
	})
}

func snapshotFirewall(plan RegistryPlan) (snapshot RegistrySnapshot, err error) {
	snapshot.RuleID = plan.RuleID
	err = withFirewallPolicy(func(policy *firewallPolicy) error {
		first, err := readFirewallScalar(policy, plan)
		if err != nil {
			return err
		}
		second, err := readFirewallScalar(policy, plan)
		if err != nil {
			return err
		}
		if first != second {
			return errors.New("local firewall setting changed during snapshot")
		}
		snapshot = RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: firewallSnapshotKind, Data: binary.LittleEndian.AppendUint32(nil, first)}
		return nil
	})
	return snapshot, err
}

func replaceFirewall(ctx context.Context, plan RegistryPlan, want, expected RegistrySnapshot) error {
	return withFirewallPolicy(func(policy *firewallPolicy) error {
		current, err := readFirewallScalar(policy, plan)
		if err != nil {
			return err
		}
		if current != binary.LittleEndian.Uint32(expected.Data) {
			return errors.New("local firewall setting changed externally before write")
		}
		profile, property, err := firewallProfile(plan)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		value := binary.LittleEndian.Uint32(want.Data)
		var result uintptr
		if property == "Enabled" {
			var enabled uintptr
			if value == 1 {
				enabled = uintptr(^uint32(0)) // VARIANT_TRUE, low16 bits are -1.
			}
			result, _, _ = syscall.SyscallN(policy.Vtbl.putEnabled, uintptr(unsafe.Pointer(policy)), uintptr(profile), enabled)
		} else {
			result, _, _ = syscall.SyscallN(policy.Vtbl.putInbound, uintptr(unsafe.Pointer(policy)), uintptr(profile), uintptr(value))
		}
		if err := hresult("INetFwPolicy2 scalar update", result); err != nil {
			return err
		}
		after, err := readFirewallScalar(policy, plan)
		if err != nil || after != value {
			return errors.New("native local firewall recheck differs from the exact requested value")
		}
		return nil
	})
}

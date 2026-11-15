package scanner

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unicode/utf16"

	"github.com/Wearden/proto/wire"
)

type RegistryPlan struct {
	RuleID, Path, Name, Provider string
	Desired                      uint32
	ValueKind                    uint32
	Text                         string
}

const accountPolicySnapshotKind uint32 = 0x10000
const auditPolicySnapshotKind uint32 = 0x10001
const serviceSnapshotKind uint32 = 0x10002
const firewallSnapshotKind uint32 = 0x10004
const guestSnapshotKind uint32 = 0x10005

var writableFirewall = map[string]uint32{
	"WIN-FW-001": 1, "WIN-FW-002": 1, "WIN-FW-003": 1,
	"WIN-FW-004": 0, "WIN-FW-005": 0, "WIN-FW-006": 0,
}

type RegistrySnapshot struct {
	RuleID string `json:"rule_id"`
	Exists bool   `json:"exists"`
	Kind   uint32 `json:"kind"`
	Data   []byte `json:"data"`
}

// Only compiled policies are writable; payloads cannot supply values or paths.
var writableDWORDs = map[string]uint32{
	"WIN-SEC-001": 0, "WIN-SEC-002": 1, "WIN-SEC-006": 1, "WIN-SEC-007": 1, "WIN-SEC-008": 0,
	"WIN-SEC-009": 1, "WIN-SEC-010": 0, "WIN-SEC-019": 1, "WIN-DEF-006": 255, "WIN-DEF-008": 1,
	"WIN-SEC-011": 1, "WIN-SEC-012": 1, "WIN-SEC-013": 1, "WIN-SEC-014": 1,
	"WIN-SEC-015": 1, "WIN-SEC-016": 1, "WIN-SEC-017": 2, "WIN-SEC-018": 1, "WIN-SEC-020": 1,
	"WIN-SMB-001": 5, "WIN-SMB-002": 1, "WIN-SMB-007": 2, "WIN-SMB-008": 537395200, "WIN-SMB-009": 1,
	"WIN-RDP-001": 1, "WIN-RDP-002": 3, "WIN-RDP-005": 1, "WIN-RDP-006": 1,
	"WIN-SEC-003": 900, "WIN-RDP-003": 900000, "WIN-RDP-004": 60000,
}

var writableAccountPolicies = map[string]uint32{
	"WIN-PWD-001": 14, "WIN-PWD-003": 5, "WIN-PWD-004": 900, "WIN-PWD-005": 900,
	"WIN-PWD-006": 5184000, "WIN-PWD-007": 86400, "WIN-PWD-008": 24,
}

var writableAuditPolicies = map[string]uint32{
	"WIN-AUD-001": 3, "WIN-AUD-002": 3, "WIN-AUD-003": 3, "WIN-AUD-004": 2,
	"WIN-AUD-005": 1, "WIN-AUD-006": 3, "WIN-AUD-007": 1, "WIN-AUD-008": 3,
	"WIN-AUD-009": 1, "WIN-AUD-010": 3, "WIN-AUD-011": 1, "WIN-AUD-012": 1,
	"WIN-AUD-013": 3, "WIN-AUD-014": 1, "WIN-AUD-015": 3, "WIN-AUD-016": 1,
	"WIN-AUD-017": 1, "WIN-AUD-018": 3,
}

func Plan(ruleID string) (RegistryPlan, error) {
	if ruleID == "WIN-SMB-004" {
		target := approvedTargets[ruleID]
		if target.Kind != "registry" || target.Path != `SYSTEM\CurrentControlSet\Services\mrxsmb10` || target.Name != "Start" {
			return RegistryPlan{}, errors.New("invalid compiled SMB driver target")
		}
		return RegistryPlan{RuleID: ruleID, Name: "mrxsmb10", Provider: "smb_driver", Desired: 4}, nil
	}

	if desired, ok := writableWMI[ruleID]; ok {
		target := approvedTargets[ruleID]
		_, known := wmiChecks[target.Name]
		if firewall, ok := firewallChecks[target.Name]; ok {
			known = target.Kind == "firewall" && (firewall.Property == "LogBlocked" || firewall.Property == "LogMaxSizeKilobytes")
		} else {
			known = known && target.Kind == "wmi"
		}
		if target.Path != "" || !known {
			return RegistryPlan{}, errors.New("invalid compiled WMI target")
		}
		return RegistryPlan{RuleID: ruleID, Name: target.Name, Provider: "wmi", Desired: desired}, nil
	}

	if ruleID == "WIN-DEF-007" {
		target := approvedTargets[ruleID]
		if target.Kind != "installer_policy" || target.Path != "" || target.Name != "AlwaysInstallElevated" {
			return RegistryPlan{}, errors.New("invalid compiled installer policy target")
		}
		return RegistryPlan{RuleID: ruleID, Path: `SOFTWARE\Policies\Microsoft\Windows\Installer`, Name: target.Name, Provider: "registry", ValueKind: 4}, nil
	}

	if ruleID == "WIN-PWD-010" {
		target := approvedTargets[ruleID]
		if target.Kind != "guest_account" || target.Path != "" || target.Name != "Guest" {
			return RegistryPlan{}, errors.New("invalid compiled Guest account target")
		}
		return RegistryPlan{RuleID: ruleID, Name: target.Name, Provider: target.Kind}, nil
	}

	if desired, ok := writableFirewall[ruleID]; ok {
		target := approvedTargets[ruleID]
		check, known := firewallChecks[target.Name]
		if target.Kind != "firewall" || target.Path != "" || !known || (check.Property != "Enabled" && check.Property != "DefaultInboundAction") {
			return RegistryPlan{}, errors.New("compiled firewall policy target is invalid")
		}
		return RegistryPlan{RuleID: ruleID, Name: target.Name, Provider: target.Kind, Desired: desired}, nil
	}
	if _, ok := writableRights[ruleID]; ok {
		target := approvedTargets[ruleID]
		if target.Kind != "user_right" || target.Path != "" || !rightNames[target.Name] {
			return RegistryPlan{}, errors.New("compiled user-right target is invalid")
		}
		return RegistryPlan{RuleID: ruleID, Name: target.Name, Provider: target.Kind}, nil
	}
	if target, ok := approvedTargets[ruleID]; ok && target.Kind == "service" && serviceNames[target.Name] && target.Path == "" {
		return RegistryPlan{RuleID: ruleID, Name: target.Name, Provider: "service", Desired: 4}, nil
	}
	if ruleID == "WIN-SEC-004" || ruleID == "WIN-SEC-005" {
		target := approvedTargets[ruleID]
		if target.Kind != "registry" || target.Path == "" || target.Name == "" {
			return RegistryPlan{}, errors.New("compiled notice target is invalid")
		}
		text := "Authorised use only"
		if ruleID == "WIN-SEC-005" {
			text = "This system is for authorised use only. Activity is monitored and logged."
		}
		return RegistryPlan{RuleID: ruleID, Path: target.Path, Name: target.Name, Provider: "registry", ValueKind: 1, Text: text}, nil
	}
	if ruleID == "WIN-SMB-010" {
		target := approvedTargets[ruleID]
		if target.Kind != "anonymous_pipes" || target.Path != "" || target.Name != "NullSessionPipes" {
			return RegistryPlan{}, errors.New("compiled anonymous-pipe target is invalid")
		}
		return RegistryPlan{RuleID: ruleID, Path: `SYSTEM\CurrentControlSet\Services\LanManServer\Parameters`, Name: target.Name, Provider: "registry", ValueKind: 7}, nil
	}
	if value, ok := writableAuditPolicies[ruleID]; ok {
		target := approvedTargets[ruleID]
		if target.Kind != "audit_policy" || target.Path != "" || auditNames[target.Name] == 0 {
			return RegistryPlan{}, errors.New("compiled audit-policy target is invalid")
		}
		return RegistryPlan{RuleID: ruleID, Name: target.Name, Desired: value, Provider: target.Kind}, nil
	}
	if value, ok := writableAccountPolicies[ruleID]; ok {
		target := approvedTargets[ruleID]
		if target.Kind != "password_policy" || target.Path != "" || target.Name == "" {
			return RegistryPlan{}, errors.New("compiled account-policy target is invalid")
		}
		return RegistryPlan{RuleID: ruleID, Name: target.Name, Desired: value, Provider: target.Kind}, nil
	}
	value, ok := writableDWORDs[ruleID]
	if !ok {
		return RegistryPlan{}, errors.New("rule is read-only, risky, or unsupported for native remediation")
	}
	target := approvedTargets[ruleID]
	if target.Kind != "registry" || target.Path == "" || target.Name == "" {
		return RegistryPlan{}, errors.New("compiled remediation target is invalid")
	}
	return RegistryPlan{RuleID: ruleID, Path: target.Path, Name: target.Name, Desired: value, Provider: target.Kind, ValueKind: 4}, nil
}

func KnownRule(ruleID string) bool { _, ok := approvedTargets[ruleID]; return ok }
func RemediationHost(benchmark string) error {
	if err := supportedOS(); err != nil {
		return err
	}
	return supportedBenchmark(benchmark)
}
func DesiredSnapshot(plan RegistryPlan, before RegistrySnapshot) RegistrySnapshot {
	if plan.Provider == "smb_driver" {
		return desiredSMBDriver(plan, before)
	}
	if plan.Provider == "wmi" {
		if !ValidSnapshot(plan, before) {
			return RegistrySnapshot{RuleID: plan.RuleID}
		}
		data := append([]byte(nil), before.Data...)
		binary.LittleEndian.PutUint64(data[8:], uint64(plan.Desired))
		return RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: wmiSnapshotKind, Data: data}
	}

	if plan.Provider == "user_right" {
		return desiredRightSnapshot(plan, before)
	}
	if plan.Provider == "service" {
		if !before.Exists {
			return before
		}
		data := binary.LittleEndian.AppendUint32(nil, 4)
		data = binary.LittleEndian.AppendUint32(data, 1)
		data = binary.LittleEndian.AppendUint32(data, 0)
		if ValidSnapshot(plan, before) {
			data = append(data, before.Data[12:]...)
		}
		return RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: serviceSnapshotKind, Data: data}
	}
	if plan.Provider == "guest_account" {
		if !ValidSnapshot(plan, before) {
			return RegistrySnapshot{RuleID: plan.RuleID}
		}
		data := append([]byte(nil), before.Data...)
		binary.LittleEndian.PutUint32(data, binary.LittleEndian.Uint32(data)|2)
		return RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: guestSnapshotKind, Data: data}
	}

	if plan.RuleID == "WIN-SMB-010" {
		return RegistrySnapshot{RuleID: plan.RuleID}
	}
	if plan.Provider == "registry" && plan.ValueKind == 1 {
		var data []byte
		for _, word := range append(utf16.Encode([]rune(plan.Text)), 0) {
			data = binary.LittleEndian.AppendUint16(data, word)
		}
		return RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: 1, Data: data}
	}
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, plan.Desired)
	return RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: snapshotKind(plan), Data: data}
}

func snapshotKind(plan RegistryPlan) uint32 {
	switch plan.Provider {
	case "registry":
		return plan.ValueKind
	case "password_policy":
		return accountPolicySnapshotKind
	case "audit_policy":
		return auditPolicySnapshotKind
	case "service":
		return serviceSnapshotKind
	case "user_right":
		return rightSnapshotKind
	case "firewall":
		return firewallSnapshotKind
	case "guest_account":
		return guestSnapshotKind
	case "wmi":
		return wmiSnapshotKind
	case "smb_driver":
		return smbDriverSnapshotKind
	default:
		return 0
	}
}

func ValidSnapshot(plan RegistryPlan, snapshot RegistrySnapshot) bool {
	kind := snapshotKind(plan)
	if kind == 0 || snapshot.RuleID != plan.RuleID {
		return false
	}
	if kind == smbDriverSnapshotKind {
		return validSMBDriverSnapshot(snapshot)
	}
	if kind == wmiSnapshotKind {
		return snapshot.Exists && snapshot.Kind == kind && validWMIData(plan, snapshot.Data)
	}
	if kind == guestSnapshotKind {
		return snapshot.Exists && snapshot.Kind == kind && len(snapshot.Data) == 36 && binary.LittleEndian.Uint32(snapshot.Data)&0x200 != 0 && !bytes.Equal(snapshot.Data[4:], make([]byte, 32))
	}

	if kind == rightSnapshotKind {
		_, err := decodeRightSIDs(snapshot.Data)
		return snapshot.Exists && snapshot.Kind == kind && err == nil
	}
	if kind == serviceSnapshotKind {
		if !snapshot.Exists {
			return snapshot.Kind == 0 && len(snapshot.Data) == 0
		}
		if snapshot.Kind != kind || len(snapshot.Data) != 44 {
			return false
		}
		start, state, delayed := binary.LittleEndian.Uint32(snapshot.Data), binary.LittleEndian.Uint32(snapshot.Data[4:]), binary.LittleEndian.Uint32(snapshot.Data[8:])
		return start >= 2 && start <= 4 && (state == 1 || state == 4) && delayed <= 1
	}
	if plan.Provider != "registry" {
		if !snapshot.Exists || snapshot.Kind != kind || len(snapshot.Data) != 4 {
			return false
		}
		value := binary.LittleEndian.Uint32(snapshot.Data)
		return (kind != auditPolicySnapshotKind || value <= 3) && (kind != firewallSnapshotKind || value <= 1)
	}
	return (!snapshot.Exists && snapshot.Kind == 0 && len(snapshot.Data) == 0) || (snapshot.Exists && snapshot.Kind == kind && validRegistryData(kind, snapshot.Data))
}

func validRegistryData(kind uint32, data []byte) bool {
	if kind == 4 {
		return len(data) == 4
	}
	if (kind != 1 && kind != 7) || len(data) < 2 || len(data) > 65536 || len(data)%2 != 0 {
		return false
	}
	words := make([]uint16, len(data)/2)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	if words[len(words)-1] != 0 {
		return false
	}
	for i := 0; i < len(words)-1; i++ {
		word := words[i]
		if word >= 0xd800 && word <= 0xdbff {
			if i+1 >= len(words)-1 || words[i+1] < 0xdc00 || words[i+1] > 0xdfff {
				return false
			}
			i++
		} else if word >= 0xdc00 && word <= 0xdfff {
			return false
		} else if word == 0 {
			if kind == 1 || (i != len(words)-2 && (i == 0 || words[i+1] == 0)) {
				return false
			}
		}
	}
	// Empty MULTI_SZ may have one or two NULs; nonempty lists require two.
	if kind == 7 && len(words) > 1 && words[len(words)-2] != 0 {
		return false
	}
	return true
}
func SameSnapshot(a, b RegistrySnapshot) bool {
	return a.RuleID == b.RuleID && a.Exists == b.Exists && a.Kind == b.Kind && bytes.Equal(a.Data, b.Data)
}

// Multi-step operations can be interrupted between native writes. Compensation
// accepts only defined intermediate states between the two journaled endpoints.
func CanRestoreSnapshot(plan RegistryPlan, current, before, target RegistrySnapshot) bool {
	if !ValidSnapshot(plan, current) || !ValidSnapshot(plan, before) || !ValidSnapshot(plan, target) {
		return false
	}
	if SameSnapshot(current, before) || SameSnapshot(current, target) {
		return true
	}
	if plan.Provider == "smb_driver" {
		return compatibleSMBDriverRestore(current, before, target)
	}
	if plan.Provider == "user_right" {
		return compatibleRightRestore(current, before, target)
	}
	if plan.Provider != "service" || !current.Exists || !before.Exists || !target.Exists {
		return false
	}
	if !bytes.Equal(current.Data[12:], before.Data[12:]) || !bytes.Equal(current.Data[12:], target.Data[12:]) {
		return false
	}
	for offset := 0; offset < 12; offset += 4 {
		value := binary.LittleEndian.Uint32(current.Data[offset:])
		if value == binary.LittleEndian.Uint32(before.Data[offset:]) || value == binary.LittleEndian.Uint32(target.Data[offset:]) {
			continue
		}
		// A previously disabled but running service needs temporary manual start
		// for exact runtime restoration; it is disabled again after starting.
		if offset == 0 && value == 3 && ((binary.LittleEndian.Uint32(before.Data) == 4 && binary.LittleEndian.Uint32(before.Data[4:]) == 4) || (binary.LittleEndian.Uint32(target.Data) == 4 && binary.LittleEndian.Uint32(target.Data[4:]) == 4)) {
			continue
		}
		return false
	}
	return true
}

func ValidApplyTarget(plan RegistryPlan, target, before RegistrySnapshot) bool {
	if !ValidSnapshot(plan, target) || !ValidSnapshot(plan, before) {
		return false
	}
	return SameSnapshot(target, DesiredSnapshot(plan, before)) || (SameSnapshot(target, before) && SnapshotStatus(plan, before) == wire.Pass)
}
func SnapshotStatus(plan RegistryPlan, snapshot RegistrySnapshot) string {
	if !ValidSnapshot(plan, snapshot) {
		return wire.Error
	}
	if plan.Provider == "smb_driver" {
		if binary.LittleEndian.Uint32(snapshot.Data) == 4 {
			return wire.Pass
		}
		return wire.Fail
	}
	if plan.RuleID == "WIN-FW-009" {
		value := binary.LittleEndian.Uint64(snapshot.Data[8:])
		if value != ^uint64(0) && value >= uint64(plan.Desired) {
			return wire.Pass
		}
		return wire.Fail
	}

	if plan.RuleID == "WIN-DEF-007" && !snapshot.Exists {
		return wire.Pass
	}
	if plan.Provider == "user_right" {
		actual, err := decodeRightSIDs(snapshot.Data)
		if err != nil {
			return wire.Error
		}
		target := writableRights[plan.RuleID]
		if target.contains {
			set := rightSIDSet(actual)
			for _, sid := range target.sids {
				if !set[string(sid)] {
					return wire.Fail
				}
			}
			return wire.Pass
		}
		data, err := encodeRightSIDs(target.sids)
		if err != nil {
			return wire.Error
		}
		if bytes.Equal(snapshot.Data, data) {
			return wire.Pass
		}
		return wire.Fail
	}
	if plan.Provider == "service" {
		if !snapshot.Exists || (binary.LittleEndian.Uint32(snapshot.Data) == 4 && binary.LittleEndian.Uint32(snapshot.Data[4:]) == 1) {
			return wire.Pass
		}
		return wire.Fail
	}
	if plan.RuleID == "WIN-SMB-010" {
		if !snapshot.Exists {
			return wire.Pass
		}
		for _, b := range snapshot.Data {
			if b != 0 {
				return wire.Fail
			}
		}
		return wire.Pass
	}
	if !snapshot.Exists {
		return wire.Error
	}
	if plan.ValueKind == 1 {
		if len(snapshot.Data) > 2 {
			return wire.Pass
		}
		return wire.Fail
	}
	switch plan.RuleID {
	case "WIN-SEC-003", "WIN-RDP-003", "WIN-RDP-004", "WIN-PWD-003", "WIN-PWD-006":
		value := binary.LittleEndian.Uint32(snapshot.Data)
		if value > 0 && value <= plan.Desired {
			return wire.Pass
		}
		return wire.Fail
	case "WIN-PWD-001", "WIN-PWD-004", "WIN-PWD-005", "WIN-PWD-007", "WIN-PWD-008":
		if binary.LittleEndian.Uint32(snapshot.Data) >= plan.Desired {
			return wire.Pass
		}
		return wire.Fail
	}
	if SameSnapshot(snapshot, DesiredSnapshot(plan, snapshot)) {
		return wire.Pass
	}
	return wire.Fail
}
func SnapshotDescription(snapshot RegistrySnapshot) string {
	if !snapshot.Exists {
		return "value absent"
	}
	if snapshot.Kind == smbDriverSnapshotKind {
		return "SMB driver startup and Workstation dependency configuration retained privately; reboot required"
	}
	if snapshot.Kind == wmiSnapshotKind {
		return "native selected WMI scalar and instance fingerprint retained privately"
	}
	if snapshot.Kind == guestSnapshotKind {
		return "local built-in Guest flags and identity fingerprint retained privately"
	}

	if snapshot.Kind == accountPolicySnapshotKind {
		return "native account-policy scalar present; exact value retained locally"
	}
	if snapshot.Kind == auditPolicySnapshotKind {
		return "native audit success/failure policy present; original flags retained locally"
	}
	if snapshot.Kind == serviceSnapshotKind {
		return "native service startup, runtime and delayed-start state retained locally"
	}
	if snapshot.Kind == rightSnapshotKind {
		return "native user-right assignments present; exact SID set retained locally"
	}
	if snapshot.Kind == firewallSnapshotKind {
		return "native local firewall profile setting retained locally"
	}
	if snapshot.Kind == 1 {
		return "REG_SZ present; exact original text retained locally"
	}
	if snapshot.Kind == 7 {
		return "REG_MULTI_SZ present; exact original list retained locally"
	}
	return "REG_DWORD present (4 bytes); exact content retained locally"
}

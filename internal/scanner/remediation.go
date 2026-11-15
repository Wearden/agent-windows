package scanner

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/Wearden/proto/wire"
)

type RegistryPlan struct {
	RuleID, Path, Name, Provider string
	Desired                      uint32
}

const accountPolicySnapshotKind uint32 = 0x10000
const auditPolicySnapshotKind uint32 = 0x10001

type RegistrySnapshot struct {
	RuleID string `json:"rule_id"`
	Exists bool   `json:"exists"`
	Kind   uint32 `json:"kind"`
	Data   []byte `json:"data"`
}

// Exact reversible DWORD policies only. Drivers, firmware-backed protection,
// operator-supplied strings require separate restore plans.
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
	return RegistryPlan{RuleID: ruleID, Path: target.Path, Name: target.Name, Desired: value, Provider: target.Kind}, nil
}

func KnownRule(ruleID string) bool { _, ok := approvedTargets[ruleID]; return ok }
func RemediationHost(benchmark string) error {
	if err := supportedOS(); err != nil {
		return err
	}
	return supportedBenchmark(benchmark)
}
func DesiredSnapshot(plan RegistryPlan) RegistrySnapshot {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, plan.Desired)
	return RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: snapshotKind(plan), Data: data}
}

func snapshotKind(plan RegistryPlan) uint32 {
	switch plan.Provider {
	case "registry":
		return 4
	case "password_policy":
		return accountPolicySnapshotKind
	case "audit_policy":
		return auditPolicySnapshotKind
	default:
		return 0
	}
}

func ValidSnapshot(plan RegistryPlan, snapshot RegistrySnapshot) bool {
	kind := snapshotKind(plan)
	if kind == 0 || snapshot.RuleID != plan.RuleID {
		return false
	}
	if kind != 4 {
		if !snapshot.Exists || snapshot.Kind != kind || len(snapshot.Data) != 4 {
			return false
		}
		return kind != auditPolicySnapshotKind || binary.LittleEndian.Uint32(snapshot.Data) <= 3
	}
	return snapshot.RuleID == plan.RuleID && ((!snapshot.Exists && snapshot.Kind == 0 && len(snapshot.Data) == 0) || (snapshot.Exists && snapshot.Kind == 4 && len(snapshot.Data) == 4))
}
func SameSnapshot(a, b RegistrySnapshot) bool {
	return a.RuleID == b.RuleID && a.Exists == b.Exists && a.Kind == b.Kind && bytes.Equal(a.Data, b.Data)
}

func ValidApplyTarget(plan RegistryPlan, target, before RegistrySnapshot) bool {
	if !ValidSnapshot(plan, target) || !ValidSnapshot(plan, before) {
		return false
	}
	return SameSnapshot(target, DesiredSnapshot(plan)) || (SameSnapshot(target, before) && SnapshotStatus(plan, before) == wire.Pass)
}
func SnapshotStatus(plan RegistryPlan, snapshot RegistrySnapshot) string {
	if !snapshot.Exists || !ValidSnapshot(plan, snapshot) {
		return wire.Error
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
	if SameSnapshot(snapshot, DesiredSnapshot(plan)) {
		return wire.Pass
	}
	return wire.Fail
}
func SnapshotDescription(snapshot RegistrySnapshot) string {
	if !snapshot.Exists {
		return "value absent"
	}
	if snapshot.Kind == accountPolicySnapshotKind {
		return "native account-policy scalar present; exact value retained locally"
	}
	if snapshot.Kind == auditPolicySnapshotKind {
		return "native audit success/failure policy present; original flags retained locally"
	}
	return "REG_DWORD present (4 bytes); exact content retained locally"
}

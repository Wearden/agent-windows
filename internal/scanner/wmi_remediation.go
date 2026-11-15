package scanner

import (
	"bytes"
	"encoding/binary"
)

const wmiSnapshotKind uint32 = 0x10006

var writableWMI = map[string]uint32{
	"WIN-SMB-003": 0, "WIN-SMB-005": 1, "WIN-SMB-006": 1,
	"WIN-DEF-001": 0, "WIN-DEF-002": 2, "WIN-DEF-003": 1,
	"WIN-DEF-004": 0, "WIN-DEF-005": 1,
	"WIN-FW-007": 1, "WIN-FW-008": 1, "WIN-FW-009": 16384,
}

func mutationWMICheck(plan RegistryPlan) wmiCheck {
	if firewall, known := firewallChecks[plan.Name]; known {
		return wmiCheck{`ROOT\StandardCimv2`, "MSFT_NetFirewallProfile", firewall.Property}
	}
	return wmiChecks[plan.Name]
}

func validWMIData(plan RegistryPlan, data []byte) bool {
	if len(data) != 48 || bytes.Equal(data[16:], make([]byte, 32)) {
		return false
	}
	kind, cim := binary.LittleEndian.Uint32(data), binary.LittleEndian.Uint32(data[4:])
	value := binary.LittleEndian.Uint64(data[8:])
	switch plan.RuleID {
	case "WIN-FW-007", "WIN-FW-008":
		return kind == 3 && cim == 18 && value <= 2
	case "WIN-FW-009":
		return kind == 8 && cim == 21 && (value <= 0xffffffff || value == ^uint64(0))
	case "WIN-SMB-003", "WIN-SMB-005", "WIN-SMB-006", "WIN-DEF-001", "WIN-DEF-004":
		return kind == 11 && cim == 11 && value <= 1
	case "WIN-DEF-002", "WIN-DEF-003", "WIN-DEF-005":
		return (kind == 17 && cim == 17 && value <= 255) || ((kind == 3 || kind == 18) && cim == 18 && value <= 65535) || ((kind == 3 || kind == 19) && cim == 19 && value <= 0xffffffff)
	}
	return false
}

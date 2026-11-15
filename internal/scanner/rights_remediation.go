package scanner

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
)

const rightSnapshotKind uint32 = 0x10003
const maxRightSIDs = 256

type rightTarget struct {
	contains bool
	sids     [][]byte
}

func builtinPolicySID(parts ...uint32) []byte {
	data := []byte{1, byte(len(parts)), 0, 0, 0, 0, 0, 5}
	for _, value := range parts {
		data = binary.LittleEndian.AppendUint32(data, value)
	}
	return data
}

var writableRights = map[string]rightTarget{
	"WIN-URA-001": {true, [][]byte{builtinPolicySID(32, 546)}},
	"WIN-URA-002": {true, [][]byte{builtinPolicySID(32, 546)}},
	"WIN-URA-003": {false, [][]byte{builtinPolicySID(32, 544)}},
	"WIN-URA-004": {false, [][]byte{builtinPolicySID(32, 544)}},
	"WIN-URA-005": {false, [][]byte{builtinPolicySID(32, 544)}},
	"WIN-URA-006": {false, nil},
	"WIN-URA-007": {false, [][]byte{builtinPolicySID(32, 544), builtinPolicySID(19), builtinPolicySID(20), builtinPolicySID(6)}},
	"WIN-URA-008": {false, [][]byte{builtinPolicySID(32, 544)}},
	"WIN-URA-009": {false, [][]byte{builtinPolicySID(32, 544)}},
	"WIN-URA-010": {true, [][]byte{builtinPolicySID(32, 544)}},
	"WIN-URA-011": {true, [][]byte{builtinPolicySID(32, 546)}},
	"WIN-URA-012": {true, [][]byte{builtinPolicySID(32, 546)}},
}

func encodeRightSIDs(sids [][]byte) ([]byte, error) {
	if len(sids) > maxRightSIDs {
		return nil, errors.New("user-right SID count exceeds256")
	}
	ordered := append([][]byte(nil), sids...)
	sort.Slice(ordered, func(i, j int) bool { return bytes.Compare(ordered[i], ordered[j]) < 0 })
	data := binary.LittleEndian.AppendUint16(nil, uint16(len(ordered)))
	for i, sid := range ordered {
		if len(sid) < 8 || sid[0] != 1 || sid[1] > 15 || len(sid) != 8+4*int(sid[1]) || (i > 0 && bytes.Equal(ordered[i-1], sid)) {
			return nil, errors.New("invalid or duplicate binary policy SID")
		}
		data = append(data, byte(len(sid)))
		data = append(data, sid...)
	}
	return data, nil
}

func decodeRightSIDs(data []byte) ([][]byte, error) {
	if len(data) < 2 || len(data) > 2+maxRightSIDs*69 {
		return nil, errors.New("invalid user-right snapshot size")
	}
	count := int(binary.LittleEndian.Uint16(data))
	if count > maxRightSIDs {
		return nil, errors.New("user-right SID count exceeds256")
	}
	remaining := data[2:]
	var sids [][]byte
	for i := 0; i < count; i++ {
		if len(remaining) < 1 {
			return nil, errors.New("truncated user-right SID length")
		}
		length := int(remaining[0])
		remaining = remaining[1:]
		if length < 8 || length > 68 || length > len(remaining) {
			return nil, errors.New("invalid user-right SID length")
		}
		sid := remaining[:length]
		if sid[0] != 1 || sid[1] > 15 || length != 8+4*int(sid[1]) || (i > 0 && bytes.Compare(sids[i-1], sid) >= 0) {
			return nil, errors.New("invalid, unordered or duplicate policy SID")
		}
		sids = append(sids, sid)
		remaining = remaining[length:]
	}
	if len(remaining) != 0 {
		return nil, errors.New("trailing user-right snapshot data")
	}
	return sids, nil
}

func rightSIDSet(sids [][]byte) map[string]bool {
	set := make(map[string]bool, len(sids))
	for _, sid := range sids {
		set[string(sid)] = true
	}
	return set
}

func desiredRightSnapshot(plan RegistryPlan, before RegistrySnapshot) RegistrySnapshot {
	target := writableRights[plan.RuleID]
	sids := append([][]byte(nil), target.sids...)
	if target.contains {
		original, err := decodeRightSIDs(before.Data)
		if err != nil {
			return RegistrySnapshot{RuleID: plan.RuleID}
		}
		seen := rightSIDSet(sids)
		for _, sid := range original {
			if !seen[string(sid)] {
				sids = append(sids, sid)
			}
		}
	}
	data, err := encodeRightSIDs(sids)
	if err != nil {
		return RegistrySnapshot{RuleID: plan.RuleID}
	}
	return RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: rightSnapshotKind, Data: data}
}

func compatibleRightRestore(current, before, target RegistrySnapshot) bool {
	c, err := decodeRightSIDs(current.Data)
	if err != nil {
		return false
	}
	b, err := decodeRightSIDs(before.Data)
	if err != nil {
		return false
	}
	t, err := decodeRightSIDs(target.Data)
	if err != nil {
		return false
	}
	currentSet, beforeSet, targetSet := rightSIDSet(c), rightSIDSet(b), rightSIDSet(t)
	for sid := range currentSet {
		if !beforeSet[sid] && !targetSet[sid] {
			return false
		}
	}
	for sid := range beforeSet {
		if targetSet[sid] && !currentSet[sid] {
			return false
		}
	}
	return true
}

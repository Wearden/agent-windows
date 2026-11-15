package scanner

const passwordFlagSnapshotKind uint32 = 0x10008

func passwordFlagPolicy(ruleID string) (name string, mask, desired uint32, known bool) {
	switch ruleID {
	case "WIN-PWD-002":
		return "complexity", 1, 1, true
	case "WIN-PWD-009":
		return "reversible_storage", 16, 0, true
	}
	return "", 0, 0, false
}

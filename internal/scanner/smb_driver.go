package scanner

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"
)

const smbDriverSnapshotKind uint32 = 0x10007

func encodeSMBDependencies(names []string) []byte {
	var words []uint16
	for _, name := range names {
		words = append(words, utf16.Encode([]rune(name))...)
		words = append(words, 0)
	}
	if len(words) == 0 {
		words = append(words, 0)
	}
	words = append(words, 0)
	data := make([]byte, 0, len(words)*2)
	for _, word := range words {
		data = binary.LittleEndian.AppendUint16(data, word)
	}
	return data
}

func decodeSMBDependencies(data []byte) ([]string, error) {
	if len(data) > 32768 || !validRegistryData(7, data) {
		return nil, errors.New("invalid SMB dependency list encoding")
	}
	var names []string
	var word []uint16
	for offset := 0; offset < len(data); offset += 2 {
		value := binary.LittleEndian.Uint16(data[offset:])
		if value != 0 {
			word = append(word, value)
			if len(word) > 256 {
				return nil, errors.New("SMB dependency name exceeds reviewed bounds")
			}
			continue
		}
		if len(word) == 0 {
			break
		}
		names = append(names, string(utf16.Decode(word)))
		word = nil
		if len(names) > 32 {
			return nil, errors.New("SMB dependency count exceeds reviewed bounds")
		}
	}
	if !bytes.Equal(encodeSMBDependencies(names), data) {
		return nil, errors.New("SMB dependency list is not canonical native text")
	}
	return names, nil
}

func withoutSMB1Dependency(data []byte) ([]byte, error) {
	names, err := decodeSMBDependencies(data)
	if err != nil {
		return nil, err
	}
	kept := names[:0]
	for _, name := range names {
		if !strings.EqualFold(name, "mrxsmb10") {
			kept = append(kept, name)
		}
	}
	return encodeSMBDependencies(kept), nil
}

func validSMBDriverSnapshot(snapshot RegistrySnapshot) bool {
	if !snapshot.Exists || snapshot.Kind != smbDriverSnapshotKind || len(snapshot.Data) < 72 || binary.LittleEndian.Uint32(snapshot.Data) > 4 || bytes.Equal(snapshot.Data[4:36], make([]byte, 32)) || bytes.Equal(snapshot.Data[36:68], make([]byte, 32)) {
		return false
	}
	_, err := decodeSMBDependencies(snapshot.Data[68:])
	return err == nil
}

func desiredSMBDriver(plan RegistryPlan, before RegistrySnapshot) RegistrySnapshot {
	if !validSMBDriverSnapshot(before) {
		return RegistrySnapshot{RuleID: plan.RuleID}
	}
	dependencies, err := withoutSMB1Dependency(before.Data[68:])
	if err != nil {
		return RegistrySnapshot{RuleID: plan.RuleID}
	}
	data := append([]byte(nil), before.Data[:68]...)
	binary.LittleEndian.PutUint32(data, 4)
	data = append(data, dependencies...)
	return RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: smbDriverSnapshotKind, Data: data}
}

func compatibleSMBDriverRestore(current, before, target RegistrySnapshot) bool {
	if !bytes.Equal(current.Data[4:68], before.Data[4:68]) || !bytes.Equal(current.Data[4:68], target.Data[4:68]) {
		return false
	}
	return (bytes.Equal(current.Data[:4], before.Data[:4]) || bytes.Equal(current.Data[:4], target.Data[:4])) && (bytes.Equal(current.Data[68:], before.Data[68:]) || bytes.Equal(current.Data[68:], target.Data[68:]))
}

//go:build windows

package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var addAccountRight = advapi.NewProc("LsaAddAccountRights")
var removeAccountRight = advapi.NewProc("LsaRemoveAccountRights")

func withRightPolicy(plan RegistryPlan, write bool, operation func(uintptr) error) (err error) {
	if !rightNames[plan.Name] || plan.Provider != "user_right" {
		return errors.New("user right is outside the compiled policy scope")
	}
	if err := localAccountPolicyHost(); err != nil {
		return err
	}
	attrs := objectAttributes{Length: uint32(unsafe.Sizeof(objectAttributes{}))}
	var policy uintptr
	// VIEW_LOCAL_INFORMATION | LOOKUP_NAMES; CREATE_ACCOUNT only for writes.
	// No private information, secret, trust, or audit-management access.
	access := uintptr(0x0001 | 0x0800)
	if write {
		access |= 0x0010
	}
	status, _, _ := openPolicy.Call(0, uintptr(unsafe.Pointer(&attrs)), access, uintptr(unsafe.Pointer(&policy)))
	if uint32(status) != 0 || policy == 0 {
		return errors.New("cannot open the local user-right policy scope")
	}
	defer func() {
		status, _, _ := closePolicy.Call(policy)
		if uint32(status) != 0 && err == nil {
			err = errors.New("cannot close local policy handle")
		}
	}()
	return operation(policy)
}

func readRightSet(policy uintptr, name string) (data []byte, err error) {
	text, err := syscall.UTF16FromString(name)
	if err != nil || !rightNames[name] {
		return nil, errors.New("invalid compiled user-right name")
	}
	right := unicodeString{Length: uint16((len(text) - 1) * 2), MaxLength: uint16(len(text) * 2), Buffer: &text[0]}
	var buffer unsafe.Pointer
	var count uint32
	status, _, _ := enumerateRight.Call(policy, uintptr(unsafe.Pointer(&right)), uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&count)))
	runtime.KeepAlive(text)
	if buffer != nil {
		defer func() {
			status, _, _ := freeLSA.Call(uintptr(buffer))
			if uint32(status) != 0 && err == nil {
				err = errors.New("cannot free user-right policy result")
			}
		}()
	}
	if uint32(status) == 0x8000001a && count == 0 {
		return encodeRightSIDs(nil)
	}
	if uint32(status) != 0 {
		return nil, fmt.Errorf("user-right enumeration failed with NTSTATUS 0x%08x", uint32(status))
	}
	if count > maxRightSIDs || (count > 0 && buffer == nil) {
		return nil, errors.New("user-right assignment count is invalid or exceeds256")
	}
	var sids [][]byte
	for _, sid := range unsafe.Slice((**windows.SID)(buffer), int(count)) {
		if sid == nil || !sid.IsValid() {
			return nil, errors.New("native policy returned an invalid SID")
		}
		length := sid.Len()
		if length < 8 || length > 68 {
			return nil, errors.New("native policy SID exceeds reviewed bounds")
		}
		sids = append(sids, append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(sid)), length)...))
	}
	return encodeRightSIDs(sids)
}

func snapshotUserRight(plan RegistryPlan) (snapshot RegistrySnapshot, err error) {
	snapshot.RuleID = plan.RuleID
	err = withRightPolicy(plan, false, func(policy uintptr) error {
		first, err := readRightSet(policy, plan.Name)
		if err != nil {
			return err
		}
		second, err := readRightSet(policy, plan.Name)
		if err != nil {
			return err
		}
		if !bytes.Equal(first, second) {
			return errors.New("user-right assignments changed during snapshot")
		}
		snapshot = RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: rightSnapshotKind, Data: first}
		return nil
	})
	return snapshot, err
}

func replaceUserRight(ctx context.Context, plan RegistryPlan, want, expected RegistrySnapshot) error {
	return withRightPolicy(plan, true, func(policy uintptr) error {
		deadline := time.Now().Add(10 * time.Second)
		if authorized, ok := ctx.Deadline(); ok && authorized.Before(deadline) {
			deadline = authorized
		}
		wantedSIDs, err := decodeRightSIDs(want.Data)
		if err != nil {
			return err
		}
		originalSIDs, err := decodeRightSIDs(expected.Data)
		if err != nil {
			return err
		}
		wantedSet, originalSet := rightSIDSet(wantedSIDs), rightSIDSet(originalSIDs)
		working := expected.Data
		text, err := syscall.UTF16FromString(plan.Name)
		if err != nil {
			return errors.New("invalid compiled user-right name")
		}
		right := unicodeString{Length: uint16((len(text) - 1) * 2), MaxLength: uint16(len(text) * 2), Buffer: &text[0]}
		mutate := func(sid []byte, add bool) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !time.Now().Before(deadline) {
				return errors.New("user-right mutation deadline exceeded")
			}
			current, err := readRightSet(policy, plan.Name)
			if err != nil {
				return err
			}
			if !bytes.Equal(current, working) {
				return errors.New("user-right assignments changed externally before a native write")
			}
			sids, err := decodeRightSIDs(working)
			if err != nil {
				return err
			}
			var next [][]byte
			for _, member := range sids {
				if !bytes.Equal(member, sid) {
					next = append(next, member)
				}
			}
			if add {
				next = append(next, sid)
			}
			nextData, err := encodeRightSIDs(next)
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if !time.Now().Before(deadline) {
				return errors.New("user-right authorization expired before native call")
			}
			// Fresh allocation provides aligned native SID storage independent of
			// the packed journal representation. Remove only this one named right.
			nativeSID := append([]byte(nil), sid...)
			var status uintptr
			if add {
				status, _, _ = addAccountRight.Call(policy, uintptr(unsafe.Pointer(&nativeSID[0])), uintptr(unsafe.Pointer(&right)), 1)
			} else {
				status, _, _ = removeAccountRight.Call(policy, uintptr(unsafe.Pointer(&nativeSID[0])), 0, uintptr(unsafe.Pointer(&right)), 1)
			}
			runtime.KeepAlive(nativeSID)
			runtime.KeepAlive(text)
			if uint32(status) != 0 {
				return fmt.Errorf("user-right update failed with NTSTATUS 0x%08x", uint32(status))
			}
			working = nextData
			return nil
		}
		// Removing extras first keeps intermediate sets within the snapshot bound.
		for _, sid := range originalSIDs {
			if !wantedSet[string(sid)] {
				if err := mutate(sid, false); err != nil {
					return err
				}
			}
		}
		for _, sid := range wantedSIDs {
			if !originalSet[string(sid)] {
				if err := mutate(sid, true); err != nil {
					return err
				}
			}
		}
		after, err := readRightSet(policy, plan.Name)
		if err != nil || !bytes.Equal(after, want.Data) {
			return errors.New("native user-right recheck differs from the exact requested SID set")
		}
		return nil
	})
}

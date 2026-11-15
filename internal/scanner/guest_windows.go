//go:build windows

package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var setUserInfo = netapi.NewProc("NetUserSetInfo")

type modals2 struct {
	Name *uint16
	SID  *windows.SID
}

type userInfo23 struct {
	Name, FullName, Comment *uint16
	Flags                   uint32
	SID                     *windows.SID
}

// Names and SIDs remain local. The snapshot contains flags plus an identity
// fingerprint, allowing renamed/localized RID501 accounts without name guessing.
func localGuestState() (string, []byte, error) {
	if err := localAccountPolicyHost(); err != nil {
		return "", nil, err
	}
	var domainData *byte
	status, _, _ := getModals.Call(0, 2, uintptr(unsafe.Pointer(&domainData)))
	if status != 0 || domainData == nil {
		return "", nil, errors.New("local SAM identity is unavailable")
	}
	defer syscall.NetApiBufferFree(domainData)
	domain := (*modals2)(unsafe.Pointer(domainData)).SID
	if domain == nil || !domain.IsValid() || domain.SubAuthorityCount() != 4 || domain.SubAuthority(0) != 21 {
		return "", nil, errors.New("local SAM identity is outside the reviewed account domain shape")
	}
	guest, err := windows.CreateWellKnownDomainSid(windows.WinAccountGuestSid, domain)
	if err != nil {
		return "", nil, errors.New("cannot derive local built-in Guest identity")
	}
	name, _, accountType, err := guest.LookupAccount("")
	if err != nil || accountType != windows.SidTypeUser || name == "" || len(name) > 256 || strings.ContainsAny(name, `\/`) {
		return "", nil, errors.New("local built-in Guest name is unavailable or ambiguous")
	}
	wide, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", nil, errors.New("invalid local Guest account name")
	}
	var data *byte
	if err := syscall.NetUserGetInfo(nil, wide, 23, &data); err != nil || data == nil {
		return "", nil, errors.New("local Guest account metadata is unavailable")
	}
	defer syscall.NetApiBufferFree(data)
	info := (*userInfo23)(unsafe.Pointer(data))
	if info.SID == nil || !info.SID.IsValid() || !info.SID.Equals(guest) || info.Flags&0x200 == 0 {
		return "", nil, errors.New("resolved account is not the local built-in Guest account")
	}
	fingerprint := sha256.Sum256(unsafe.Slice((*byte)(unsafe.Pointer(guest)), guest.Len()))
	state := binary.LittleEndian.AppendUint32(nil, info.Flags)
	state = append(state, fingerprint[:]...)
	runtime.KeepAlive(guest)
	return name, state, nil
}

func snapshotGuest(plan RegistryPlan) (RegistrySnapshot, error) {
	_, data, err := localGuestState()
	if err != nil {
		return RegistrySnapshot{RuleID: plan.RuleID}, err
	}
	return RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: guestSnapshotKind, Data: data}, nil
}

func replaceGuest(ctx context.Context, plan RegistryPlan, want, expected RegistrySnapshot) error {
	if !bytes.Equal(want.Data[4:], expected.Data[4:]) || (binary.LittleEndian.Uint32(want.Data)^binary.LittleEndian.Uint32(expected.Data))&^uint32(2) != 0 {
		return errors.New("Guest mutation may change only the disabled flag of the same local identity")
	}
	name, current, err := localGuestState()
	if err != nil || !bytes.Equal(current, expected.Data) {
		return errors.New("Guest account identity or flags changed externally")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	wide, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return errors.New("invalid local Guest account name")
	}
	flags := binary.LittleEndian.Uint32(want.Data)
	var parameter uint32
	status, _, _ := setUserInfo.Call(0, uintptr(unsafe.Pointer(wide)), 1008, uintptr(unsafe.Pointer(&flags)), uintptr(unsafe.Pointer(&parameter)))
	runtime.KeepAlive(wide)
	runtime.KeepAlive(flags)
	if status != 0 {
		return errors.New("local Guest disabled-flag update failed")
	}
	after, err := snapshotGuest(plan)
	if err != nil || !SameSnapshot(after, want) {
		return errors.New("local Guest flag recheck did not match requested state")
	}
	return nil
}

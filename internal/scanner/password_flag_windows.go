//go:build windows

package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var samLibrary = windows.NewLazySystemDLL("samlib.dll")
var samConnect = samLibrary.NewProc("SamConnect")
var samOpenDomain = samLibrary.NewProc("SamOpenDomain")
var samQueryDomain = samLibrary.NewProc("SamQueryInformationDomain")
var samSetDomain = samLibrary.NewProc("SamSetInformationDomain")
var samClose = samLibrary.NewProc("SamCloseHandle")
var samFree = samLibrary.NewProc("SamFreeMemory")

type samPasswordPolicy struct {
	MinLength, History uint16
	Properties         uint32
	MaxAge, MinAge     int64
}

func samStatus(operation string, status uintptr) error {
	if uint32(status) != 0 {
		return fmt.Errorf("%s status 0x%08x", operation, uint32(status))
	}
	return nil
}

func localSAMDomainSID() (sid *windows.SID, err error) {
	if err := localAccountPolicyHost(); err != nil {
		return nil, err
	}
	var data *byte
	status, _, _ := getModals.Call(0, 2, uintptr(unsafe.Pointer(&data)))
	if status != 0 || data == nil {
		return nil, errors.New("local SAM domain metadata is unavailable")
	}
	defer func() { err = errors.Join(err, syscall.NetApiBufferFree(data)) }()
	domain := (*modals2)(unsafe.Pointer(data)).SID
	if domain == nil || !domain.IsValid() || domain.SubAuthorityCount() != 4 || domain.SubAuthority(0) != 21 {
		return nil, errors.New("local SAM domain identity requires review")
	}
	return domain.Copy()
}

func withSAMPasswordPolicy(write bool, operation func(uintptr, [32]byte) error) (err error) {
	sid, err := localSAMDomainSID()
	if err != nil {
		return err
	}
	for _, proc := range []*windows.LazyProc{samConnect, samOpenDomain, samQueryDomain, samClose, samFree} {
		if proc.Find() != nil {
			return errors.New("native SAM policy API is unavailable")
		}
	}
	if write && samSetDomain.Find() != nil {
		return errors.New("native SAM policy setter is unavailable")
	}
	var server uintptr
	// Local server only; CONNECT | LOOKUP_DOMAIN, no supplied credentials.
	status, _, _ := samConnect.Call(0, uintptr(unsafe.Pointer(&server)), 0x21, 0)
	if err := samStatus("SamConnect(local policy)", status); err != nil {
		return err
	}
	if server == 0 {
		return errors.New("native SAM returned an empty local handle")
	}
	defer func() {
		status, _, _ := samClose.Call(server)
		err = errors.Join(err, samStatus("SamCloseHandle(server)", status))
	}()
	access := uintptr(1) // DOMAIN_READ_PASSWORD_PARAMETERS.
	if write {
		access |= 2 // DOMAIN_WRITE_PASSWORD_PARAMS, no user/secret rights.
	}
	var domain uintptr
	status, _, _ = samOpenDomain.Call(server, access, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&domain)))
	runtime.KeepAlive(sid)
	if err := samStatus("SamOpenDomain(local policy)", status); err != nil {
		return err
	}
	if domain == 0 {
		return errors.New("native SAM returned an empty domain handle")
	}
	defer func() {
		status, _, _ := samClose.Call(domain)
		err = errors.Join(err, samStatus("SamCloseHandle(domain)", status))
	}()
	fingerprint := sha256.Sum256(unsafe.Slice((*byte)(unsafe.Pointer(sid)), sid.Len()))
	runtime.KeepAlive(sid)
	return operation(domain, fingerprint)
}

// DomainPasswordInformation contains policy metadata, not hashes or passwords.
func querySAMPasswordPolicy(domain uintptr) (policy samPasswordPolicy, err error) {
	var data *byte
	status, _, _ := samQueryDomain.Call(domain, 1, uintptr(unsafe.Pointer(&data)))
	if err := samStatus("SamQueryInformationDomain(password policy)", status); err != nil {
		return policy, err
	}
	if data == nil {
		return policy, errors.New("native password policy metadata is empty")
	}
	defer func() {
		status, _, _ := samFree.Call(uintptr(unsafe.Pointer(data)))
		err = errors.Join(err, samStatus("SamFreeMemory(policy)", status))
	}()
	return *(*samPasswordPolicy)(unsafe.Pointer(data)), nil
}

func samFlagSnapshot(plan RegistryPlan, policy samPasswordPolicy, fingerprint [32]byte) RegistrySnapshot {
	_, mask, _, _ := passwordFlagPolicy(plan.RuleID)
	var value uint32
	if policy.Properties&mask != 0 {
		value = 1
	}
	data := binary.LittleEndian.AppendUint32(nil, value)
	data = append(data, fingerprint[:]...)
	return RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: passwordFlagSnapshotKind, Data: data}
}

func snapshotPasswordFlag(plan RegistryPlan) (snapshot RegistrySnapshot, err error) {
	err = withSAMPasswordPolicy(false, func(domain uintptr, fingerprint [32]byte) error {
		policy, err := querySAMPasswordPolicy(domain)
		if err != nil {
			return err
		}
		snapshot = samFlagSnapshot(plan, policy, fingerprint)
		return nil
	})
	return snapshot, err
}

func passwordFlagValue(ruleID string) (string, error) {
	name, _, desired, known := passwordFlagPolicy(ruleID)
	if !known {
		return "", errors.New("unreviewed password policy flag")
	}
	snapshot, err := snapshotPasswordFlag(RegistryPlan{RuleID: ruleID, Name: name, Provider: "password_flag", Desired: desired})
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(snapshot.Data)), 10), nil
}

func replacePasswordFlag(ctx context.Context, plan RegistryPlan, want, expected RegistrySnapshot) error {
	if !bytes.Equal(want.Data[4:], expected.Data[4:]) {
		return errors.New("password policy replacement must retain the same local domain identity")
	}
	return withSAMPasswordPolicy(true, func(domain uintptr, fingerprint [32]byte) error {
		policy, err := querySAMPasswordPolicy(domain)
		if err != nil {
			return err
		}
		if !SameSnapshot(samFlagSnapshot(plan, policy, fingerprint), expected) {
			return errors.New("selected password policy flag or local domain changed externally")
		}
		_, mask, _, _ := passwordFlagPolicy(plan.RuleID)
		updated := policy
		updated.Properties &^= mask
		if binary.LittleEndian.Uint32(want.Data) == 1 {
			updated.Properties |= mask
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		status, _, _ := samSetDomain.Call(domain, 1, uintptr(unsafe.Pointer(&updated)))
		runtime.KeepAlive(updated)
		if err := samStatus("SamSetInformationDomain(selected policy flag)", status); err != nil {
			return err
		}
		after, err := querySAMPasswordPolicy(domain)
		if err != nil || after != updated || !SameSnapshot(samFlagSnapshot(plan, after, fingerprint), want) {
			return errors.New("password policy recheck did not match the requested selected flag and retained fields")
		}
		return nil
	})
}

//go:build windows

package scanner

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var advapi = windows.NewLazySystemDLL("advapi32.dll")
var netapi = windows.NewLazySystemDLL("netapi32.dll")
var getModals = netapi.NewProc("NetUserModalsGet")
var openPolicy = advapi.NewProc("LsaOpenPolicy")
var closePolicy = advapi.NewProc("LsaClose")
var enumerateRight = advapi.NewProc("LsaEnumerateAccountsWithUserRight")
var freeLSA = advapi.NewProc("LsaFreeMemory")
var queryAudit = advapi.NewProc("AuditQuerySystemPolicy")
var freeAudit = advapi.NewProc("AuditFree")
var openSCManager = advapi.NewProc("OpenSCManagerW")
var openService = advapi.NewProc("OpenServiceW")
var closeService = advapi.NewProc("CloseServiceHandle")
var queryService = advapi.NewProc("QueryServiceConfigW")

type modals0 struct{ MinLength, MaxAge, MinAge, ForceLogoff, History uint32 }
type modals3 struct{ Duration, Window, Threshold uint32 }
type userInfo20 struct {
	Name, FullName, Comment *uint16
	Flags, RID              uint32
}
type unicodeString struct {
	Length, MaxLength uint16
	Buffer            *uint16
}
type objectAttributes struct {
	Length                              uint32
	RootDirectory                       uintptr
	ObjectName                          *unicodeString
	Attributes                          uint32
	SecurityDescriptor, SecurityQuality uintptr
}
type auditInfo struct {
	Subcategory syscall.GUID
	Settings    uint32
	Category    syscall.GUID
}

func nativeValue(r Rule) (string, error) {
	switch r.Kind {
	case "registry":
		return registryValue(r.Path, r.Name)
	case "password_policy":
		return passwordPolicy(r.Name)
	case "user_right":
		return userRight(r.Name)
	case "audit_policy":
		return auditPolicy(r.Name)
	case "service":
		return serviceStart(r.Name)
	case "guest_account":
		return guestEnabled()
	case "installer_policy":
		value, err := registryValue(`SOFTWARE\Policies\Microsoft\Windows\Installer`, "AlwaysInstallElevated")
		if err == syscall.ERROR_FILE_NOT_FOUND || err == syscall.ERROR_PATH_NOT_FOUND {
			return "0", nil
		}
		return value, err
	case "anonymous_pipes":
		return anonymousPipes()
	case "wmi":
		return wmiValue(r.Name)
	case "firewall":
		return wmiValue(r.Name)
	default:
		return "", errors.New("unimplemented native provider")
	}
}

func passwordPolicy(name string) (string, error) {
	var data *byte
	level := uintptr(0)
	if name == "lockout_duration_seconds" || name == "lockout_window_seconds" || name == "lockout_threshold" {
		level = 3
	}
	status, _, _ := getModals.Call(0, level, uintptr(unsafe.Pointer(&data)))
	if status != 0 {
		return "", fmt.Errorf("NetUserModalsGet status %d", status)
	}
	if data == nil {
		return "", errors.New("empty modal policy result")
	}
	defer syscall.NetApiBufferFree(data)
	var value uint32
	if level == 0 {
		p := (*modals0)(unsafe.Pointer(data))
		switch name {
		case "min_length":
			value = p.MinLength
		case "max_age_seconds":
			value = p.MaxAge
		case "min_age_seconds":
			value = p.MinAge
		case "history_length":
			value = p.History
		default:
			return "", errors.New("unknown password policy field")
		}
	} else {
		p := (*modals3)(unsafe.Pointer(data))
		switch name {
		case "lockout_duration_seconds":
			value = p.Duration
		case "lockout_window_seconds":
			value = p.Window
		case "lockout_threshold":
			value = p.Threshold
		default:
			return "", errors.New("unknown lockout policy field")
		}
	}
	return strconv.FormatUint(uint64(value), 10), nil
}

func guestEnabled() (string, error) {
	name, err := syscall.UTF16PtrFromString("Guest")
	if err != nil {
		return "", err
	}
	var data *byte
	err = syscall.NetUserGetInfo(nil, name, 20, &data)
	// A missing English name may mean a localized or renamed enabled Guest account.
	if err == syscall.Errno(2221) {
		return "", errors.New("Guest name was not found; renamed/localized account requires SID-based discovery")
	}
	if err != nil {
		return "", err
	}
	if data == nil {
		return "", errors.New("empty Guest account result")
	}
	defer syscall.NetApiBufferFree(data)
	info := (*userInfo20)(unsafe.Pointer(data))
	if info.RID != 501 {
		return "", errors.New("Guest name does not identify the built-in RID 501 account")
	}
	if info.Flags&2 != 0 {
		return "False", nil
	}
	return "True", nil
}

func userRight(name string) (string, error) {
	attrs := objectAttributes{Length: uint32(unsafe.Sizeof(objectAttributes{}))}
	var policy uintptr
	// POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES. No secret or account data access.
	status, _, _ := openPolicy.Call(0, uintptr(unsafe.Pointer(&attrs)), 0x0001|0x0800, uintptr(unsafe.Pointer(&policy)))
	if uint32(status) != 0 {
		return "", fmt.Errorf("LsaOpenPolicy status 0x%x", uint32(status))
	}
	defer closePolicy.Call(policy)
	text, err := syscall.UTF16FromString(name)
	if err != nil {
		return "", err
	}
	right := unicodeString{Length: uint16((len(text) - 1) * 2), MaxLength: uint16(len(text) * 2), Buffer: &text[0]}
	var buffer unsafe.Pointer
	var count uint32
	status, _, _ = enumerateRight.Call(policy, uintptr(unsafe.Pointer(&right)), uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&count)))
	runtime.KeepAlive(text)
	if uint32(status) == 0x8000001a {
		return "", nil
	}
	if uint32(status) != 0 {
		return "", fmt.Errorf("LsaEnumerateAccountsWithUserRight status 0x%x", uint32(status))
	}
	if buffer != nil {
		defer freeLSA.Call(uintptr(buffer))
	}
	if count > 10000 || (count > 0 && buffer == nil) {
		return "", errors.New("invalid user right result")
	}
	entries := unsafe.Slice((**syscall.SID)(buffer), int(count))
	result := ""
	for _, sid := range entries {
		if sid == nil {
			return "", errors.New("invalid SID in policy result")
		}
		value, err := sid.String()
		if err != nil {
			return "", err
		}
		if len(result) > 0 {
			result += ","
		}
		result += value
	}
	return result, nil
}

func auditPolicy(name string) (string, error) {
	guid, err := auditSubcategory(name)
	if err != nil {
		return "", err
	}
	var info *auditInfo
	ok, _, err := queryAudit.Call(uintptr(unsafe.Pointer(&guid)), 1, uintptr(unsafe.Pointer(&info)))
	if ok&0xff == 0 {
		return "", fmt.Errorf("AuditQuerySystemPolicy: %w", err)
	}
	if info == nil {
		return "", errors.New("empty system audit policy")
	}
	defer freeAudit.Call(uintptr(unsafe.Pointer(info)))
	if info.Subcategory != guid {
		return "", errors.New("audit policy returned mismatched subcategory")
	}
	if info.Settings&^uint32(7) != 0 || (info.Settings&4 != 0 && info.Settings&3 != 0) {
		return "", errors.New("invalid audit policy flags")
	}
	// Success/failure flags are independent of the NONE flag; only these flags are compared.
	return strconv.FormatUint(uint64(info.Settings&3), 10), nil
}

func auditSubcategory(name string) (syscall.GUID, error) {
	value := auditNames[name]
	if value == 0 {
		return syscall.GUID{}, errors.New("unknown compiled audit subcategory")
	}
	return syscall.GUID{Data1: value, Data2: 0x69ae, Data3: 0x11d9, Data4: [8]byte{0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}, nil
}

func serviceStart(name string) (string, error) {
	manager, _, err := openSCManager.Call(0, 0, 1)
	if manager == 0 {
		return "", fmt.Errorf("OpenSCManager: %w", err)
	}
	defer closeService.Call(manager)
	serviceName, e := syscall.UTF16PtrFromString(name)
	if e != nil {
		return "", e
	}
	service, _, err := openService.Call(manager, uintptr(unsafe.Pointer(serviceName)), 1|4)
	if service == 0 {
		if err == syscall.Errno(1060) {
			return "Disabled", nil
		}
		return "", fmt.Errorf("OpenService: %w", err)
	}
	defer closeService.Call(service)
	var needed uint32
	ok, _, err := queryService.Call(service, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if ok != 0 || err != syscall.ERROR_INSUFFICIENT_BUFFER || needed < 12 || needed > 8192 {
		return "", errors.New("invalid service configuration size")
	}
	buf := make([]byte, needed)
	ok, _, err = queryService.Call(service, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&needed)))
	if ok == 0 {
		return "", fmt.Errorf("QueryServiceConfig: %w", err)
	}
	// dwStartType is the second DWORD, independent of pointer size and alignment.
	start := *(*uint32)(unsafe.Pointer(&buf[4]))
	if start == 4 {
		state, err := serviceRuntime(windows.Handle(service))
		if err != nil {
			return "", err
		}
		switch state {
		case windows.SERVICE_STOPPED:
			return "Disabled", nil
		case windows.SERVICE_RUNNING, windows.SERVICE_PAUSED:
			return "NotStopped", nil
		default:
			return "", errors.New("service runtime transition prevents a stable disabled-state observation")
		}
	}
	return "Enabled", nil
}

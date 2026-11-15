//go:build windows

package scanner

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Prefix layouts follow the official WinSDK WbemCli.h C vtables. No Invoke,
// ExecMethod, scripting, arbitrary namespace, query, or credentials are exposed.
// Reviewed mutations use only the separate mandatory partial-update path.
type unknownVtbl struct{ QueryInterface, AddRef, Release uintptr }
type locatorVtbl struct {
	unknownVtbl
	ConnectServer uintptr
}
type servicesVtbl struct {
	unknownVtbl
	OpenNamespace, CancelAsyncCall, QueryObjectSink, GetObject, GetObjectAsync                                      uintptr
	PutClass, PutClassAsync, DeleteClass, DeleteClassAsync, CreateClassEnum, CreateClassEnumAsync                   uintptr
	PutInstance, PutInstanceAsync, DeleteInstance, DeleteInstanceAsync, CreateInstanceEnum, CreateInstanceEnumAsync uintptr
	ExecQuery                                                                                                       uintptr
}
type enumVtbl struct {
	unknownVtbl
	Reset, Next uintptr
}
type classVtbl struct {
	unknownVtbl
	GetQualifierSet, Get                                                                   uintptr
	Put, Delete, GetNames, BeginEnumeration, Next, EndEnumeration, GetPropertyQualifierSet uintptr
}
type qualifierVtbl struct {
	unknownVtbl
	Get uintptr
}
type comQualifier struct{ Vtbl *qualifierVtbl }
type comLocator struct{ Vtbl *locatorVtbl }
type comServices struct{ Vtbl *servicesVtbl }
type comEnum struct{ Vtbl *enumVtbl }
type comClass struct{ Vtbl *classVtbl }

// VARIANT's value union includes the two-pointer record member on both ABIs.
type variant struct {
	Kind     uint16
	Reserved [3]uint16
	Data     [2]uintptr
}

var wmiInit sync.Once
var wmiInitError error
var initializeCOM, uninitializeCOM, initializeSecurity, createCOM, setProxy, allocBSTR, freeBSTR, clearVariant *syscall.Proc
var stringLen, arrayDim, arrayLBound, arrayUBound, arrayElement *syscall.Proc
var arrayCreateVector, arrayPutElement, arrayDestroy *syscall.Proc
var securityOnce sync.Once
var securityError error

func loadSystemLibrary(name string) (*syscall.DLL, error) {
	buf := make([]uint16, 32768)
	getDirectory := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemDirectoryW")
	n, _, err := getDirectory.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || n >= uintptr(len(buf)) {
		return nil, fmt.Errorf("GetSystemDirectoryW: %w", err)
	}
	path := filepath.Join(syscall.UTF16ToString(buf[:n]), name)
	handle, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, err
	}
	return &syscall.DLL{Name: path, Handle: syscall.Handle(handle)}, nil
}

func initializeWMI() error {
	wmiInit.Do(func() {
		ole, err := loadSystemLibrary("ole32.dll")
		if err != nil {
			wmiInitError = err
			return
		}
		aut, err := loadSystemLibrary("oleaut32.dll")
		if err != nil {
			wmiInitError = err
			return
		}
		for name, destination := range map[string]**syscall.Proc{"CoInitializeEx": &initializeCOM, "CoUninitialize": &uninitializeCOM, "CoInitializeSecurity": &initializeSecurity, "CoCreateInstance": &createCOM, "CoSetProxyBlanket": &setProxy} {
			proc, err := ole.FindProc(name)
			if err != nil {
				wmiInitError = err
				return
			}
			*destination = proc
		}
		for name, destination := range map[string]**syscall.Proc{"SysAllocStringLen": &allocBSTR, "SysFreeString": &freeBSTR, "VariantClear": &clearVariant, "SysStringLen": &stringLen, "SafeArrayGetDim": &arrayDim, "SafeArrayGetLBound": &arrayLBound, "SafeArrayGetUBound": &arrayUBound, "SafeArrayGetElement": &arrayElement, "SafeArrayCreateVector": &arrayCreateVector, "SafeArrayPutElement": &arrayPutElement, "SafeArrayDestroy": &arrayDestroy} {
			proc, err := aut.FindProc(name)
			if err != nil {
				wmiInitError = err
				return
			}
			*destination = proc
		}
	})
	return wmiInitError
}

func hresult(operation string, value uintptr) error {
	if int32(value) < 0 {
		return fmt.Errorf("%s HRESULT 0x%08x", operation, uint32(value))
	}
	return nil
}

func bstr(text string) (uintptr, error) {
	u, err := syscall.UTF16FromString(text)
	if err != nil {
		return 0, err
	}
	p, _, _ := allocBSTR.Call(uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1))
	runtime.KeepAlive(u)
	if p == 0 {
		return 0, errors.New("cannot allocate WMI string")
	}
	return p, nil
}

func releaseCOM(object unsafe.Pointer) {
	if object != nil {
		vtbl := *(**unknownVtbl)(object)
		syscall.SyscallN(vtbl.Release, uintptr(object))
	}
}

func secureProxy(object unsafe.Pointer) error {
	result, _, _ := setProxy.Call(uintptr(object), 10, 0, 0, 3, 3, 0, 0)
	return hresult("CoSetProxyBlanket", result)
}

func wmiValue(name string) (string, error) {
	return withWMIScalar(name, nil)
}

func withWMIScalar(name string, operation func(*comServices, *comClass, variant, uint32) error) (string, error) {
	check, ok := wmiChecks[name]
	firewall, isFirewall := firewallChecks[name]
	if isFirewall {
		check = wmiCheck{`ROOT\StandardCimv2`, "MSFT_NetFirewallProfile", firewall.Property}
		ok = true
	}
	if !ok {
		return "", errors.New("WMI property is not allowlisted")
	}
	if err := initializeWMI(); err != nil {
		return "", err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result, _, _ := initializeCOM.Call(0, 0)
	if err := hresult("CoInitializeEx", result); err != nil {
		return "", err
	}
	defer uninitializeCOM.Call()
	securityOnce.Do(func() {
		result, _, _ := initializeSecurity.Call(0, ^uintptr(0), 0, 0, 0, 3, 0, 0, 0)
		if uint32(result) != 0x80010119 {
			securityError = hresult("CoInitializeSecurity", result)
		}
	})
	if securityError != nil {
		return "", securityError
	}
	clsid := syscall.GUID{Data1: 0x4590f811, Data2: 0x1d3a, Data3: 0x11d0, Data4: [8]byte{0x89, 0x1f, 0, 0xaa, 0, 0x4b, 0x2e, 0x24}}
	iid := syscall.GUID{Data1: 0xdc12a687, Data2: 0x737f, Data3: 0x11cf, Data4: [8]byte{0x88, 0x4d, 0, 0xaa, 0, 0x4b, 0x2e, 0x24}}
	var locator *comLocator
	result, _, _ = createCOM.Call(uintptr(unsafe.Pointer(&clsid)), 0, 1, uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&locator)))
	if err := hresult("CoCreateInstance", result); err != nil {
		return "", err
	}
	if locator == nil {
		return "", errors.New("empty WMI locator")
	}
	defer releaseCOM(unsafe.Pointer(locator))
	namespace, err := bstr(check.Namespace)
	if err != nil {
		return "", err
	}
	defer freeBSTR.Call(namespace)
	var services *comServices
	result, _, _ = syscall.SyscallN(locator.Vtbl.ConnectServer, uintptr(unsafe.Pointer(locator)), namespace, 0, 0, 0, 0x80, 0, 0, uintptr(unsafe.Pointer(&services)))
	if err := hresult("IWbemLocator.ConnectServer", result); err != nil {
		return "", err
	}
	if services == nil {
		return "", errors.New("empty WMI service")
	}
	defer releaseCOM(unsafe.Pointer(services))
	if err = secureProxy(unsafe.Pointer(services)); err != nil {
		return "", err
	}
	language, err := bstr("WQL")
	if err != nil {
		return "", err
	}
	defer freeBSTR.Call(language)
	queryText := "SELECT " + check.Property + " FROM " + check.Class
	if operation != nil {
		// Retain native instance keys for PutInstance; only the selected scalar
		// and relative-identity fingerprint enter the private snapshot.
		queryText = "SELECT * FROM " + check.Class
	}
	if isFirewall {
		queryText += " WHERE Name = '" + firewall.Profile + "'"
	}
	query, err := bstr(queryText)
	if err != nil {
		return "", err
	}
	defer freeBSTR.Call(query)
	var enumerator *comEnum
	// WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY.
	result, _, _ = syscall.SyscallN(services.Vtbl.ExecQuery, uintptr(unsafe.Pointer(services)), language, query, 0x10|0x20, 0, uintptr(unsafe.Pointer(&enumerator)))
	if err := hresult("IWbemServices.ExecQuery", result); err != nil {
		return "", err
	}
	if enumerator == nil {
		return "", errors.New("empty WMI enumerator")
	}
	defer releaseCOM(unsafe.Pointer(enumerator))
	if err = secureProxy(unsafe.Pointer(enumerator)); err != nil {
		return "", err
	}
	var object *comClass
	var count uint32
	result, _, _ = syscall.SyscallN(enumerator.Vtbl.Next, uintptr(unsafe.Pointer(enumerator)), 5000, 1, uintptr(unsafe.Pointer(&object)), uintptr(unsafe.Pointer(&count)))
	if err := hresult("IEnumWbemClassObject.Next", result); err != nil {
		return "", err
	}
	if count != 1 || object == nil {
		return "", errors.New("WMI singleton instance missing or timed out")
	}
	defer releaseCOM(unsafe.Pointer(object))
	property, err := syscall.UTF16PtrFromString(check.Property)
	if err != nil {
		return "", err
	}
	var value variant
	var cimType uint32
	result, _, _ = syscall.SyscallN(object.Vtbl.Get, uintptr(unsafe.Pointer(object)), uintptr(unsafe.Pointer(property)), 0, uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&cimType)), 0)
	if err := hresult("IWbemClassObject.Get", result); err != nil {
		return "", err
	}
	defer clearVariant.Call(uintptr(unsafe.Pointer(&value)))
	// Refuse ambiguous singleton providers rather than silently accepting the first result.
	var extra *comClass
	count = 0
	result, _, _ = syscall.SyscallN(enumerator.Vtbl.Next, uintptr(unsafe.Pointer(enumerator)), 5000, 1, uintptr(unsafe.Pointer(&extra)), uintptr(unsafe.Pointer(&count)))
	if extra != nil {
		releaseCOM(unsafe.Pointer(extra))
	}
	if err := hresult("IEnumWbemClassObject.Next", result); err != nil {
		return "", err
	}
	if count != 0 || result != 1 {
		return "", errors.New("WMI singleton result is ambiguous or timed out")
	}
	if operation != nil {
		return "", operation(services, object, value, cimType)
	}
	if isFirewall {
		if check.Property == "LogMaxSizeKilobytes" {
			// CIM uint64 is transported as VT_BSTR by the documented WMI Automation mapping.
			if cimType != 21 || value.Kind != 8 {
				return "", errors.New("firewall log size is not a CIM uint64 string")
			}
			text, err := readBSTR(value.Data[0])
			if err != nil {
				return "", err
			}
			n, err := strconv.ParseUint(text, 0, 64)
			if err != nil {
				return "", errors.New("invalid firewall log size")
			}
			return strconv.FormatUint(n, 10), nil
		}
		if cimType != 18 || value.Kind != 3 {
			return "", errors.New("firewall setting is not the documented CIM uint16 enumeration")
		}
		integer := int32(value.Data[0])
		if integer < 0 || integer > 65535 {
			return "", errors.New("firewall enumeration is outside uint16 range")
		}
		return firewallEnum(services, check.Property, uint32(integer))
	}
	switch value.Kind {
	case 11:
		b := int16(value.Data[0])
		if b == 0 {
			return "False", nil
		}
		if b == -1 {
			return "True", nil
		}
		return "", errors.New("invalid WMI Boolean")
	case 17:
		return strconv.FormatUint(uint64(uint8(value.Data[0])), 10), nil
	case 18:
		return strconv.FormatUint(uint64(uint16(value.Data[0])), 10), nil
	case 19:
		return strconv.FormatUint(uint64(uint32(value.Data[0])), 10), nil
	case 2:
		return strconv.FormatInt(int64(int16(value.Data[0])), 10), nil
	case 3:
		return strconv.FormatInt(int64(int32(value.Data[0])), 10), nil
	default:
		return "", errors.New("WMI property is null or has an unexpected type")
	}
}

func readBSTR(value uintptr) (string, error) {
	if value == 0 {
		return "", errors.New("missing WMI BSTR")
	}
	n, _, _ := stringLen.Call(value)
	if n > 4096 {
		return "", errors.New("WMI string exceeds limit")
	}
	text := string(utf16.Decode(unsafe.Slice((*uint16)(unsafe.Pointer(value)), int(n))))
	if strings.ContainsRune(text, 0) {
		return "", errors.New("WMI string contains an embedded NUL")
	}
	return text, nil
}

func qualifierStrings(qualifiers *comQualifier, name string) ([]string, bool, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, false, err
	}
	var value variant
	result, _, _ := syscall.SyscallN(qualifiers.Vtbl.Get, uintptr(unsafe.Pointer(qualifiers)), uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(&value)), 0)
	if uint32(result) == 0x80041002 {
		return nil, false, nil
	}
	if err := hresult("IWbemQualifierSet.Get", result); err != nil {
		return nil, false, err
	}
	defer clearVariant.Call(uintptr(unsafe.Pointer(&value)))
	if value.Kind != 0x2008 || value.Data[0] == 0 {
		return nil, false, errors.New("firewall qualifier is not a BSTR array")
	}
	dim, _, _ := arrayDim.Call(value.Data[0])
	if dim != 1 {
		return nil, false, errors.New("firewall qualifier array is not one-dimensional")
	}
	var low, high int32
	result, _, _ = arrayLBound.Call(value.Data[0], 1, uintptr(unsafe.Pointer(&low)))
	if err := hresult("SafeArrayGetLBound", result); err != nil {
		return nil, false, err
	}
	result, _, _ = arrayUBound.Call(value.Data[0], 1, uintptr(unsafe.Pointer(&high)))
	if err := hresult("SafeArrayGetUBound", result); err != nil {
		return nil, false, err
	}
	length := int64(high) - int64(low) + 1
	if length < 1 || length > 128 {
		return nil, false, errors.New("firewall qualifier array has invalid length")
	}
	entries := make([]string, 0, int(length))
	for offset := int64(0); offset < length; offset++ {
		index := int32(int64(low) + offset)
		var element uintptr
		result, _, _ = arrayElement.Call(value.Data[0], uintptr(unsafe.Pointer(&index)), uintptr(unsafe.Pointer(&element)))
		if err := hresult("SafeArrayGetElement", result); err != nil {
			return nil, false, err
		}
		text, err := readBSTR(element)
		freeBSTR.Call(element)
		if err != nil {
			return nil, false, err
		}
		entries = append(entries, text)
	}
	return entries, true, nil
}

func firewallEnum(services *comServices, property string, number uint32) (string, error) {
	path, err := bstr("MSFT_NetFirewallProfile")
	if err != nil {
		return "", err
	}
	defer freeBSTR.Call(path)
	var definition *comClass
	result, _, _ := syscall.SyscallN(services.Vtbl.GetObject, uintptr(unsafe.Pointer(services)), path, 0, 0, uintptr(unsafe.Pointer(&definition)), 0)
	if err := hresult("IWbemServices.GetObject", result); err != nil {
		return "", err
	}
	if definition == nil {
		return "", errors.New("firewall class definition is missing")
	}
	defer releaseCOM(unsafe.Pointer(definition))
	p, err := syscall.UTF16PtrFromString(property)
	if err != nil {
		return "", err
	}
	var qualifiers *comQualifier
	result, _, _ = syscall.SyscallN(definition.Vtbl.GetPropertyQualifierSet, uintptr(unsafe.Pointer(definition)), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&qualifiers)))
	if err := hresult("IWbemClassObject.GetPropertyQualifierSet", result); err != nil {
		return "", err
	}
	if qualifiers == nil {
		return "", errors.New("firewall property qualifier set is missing")
	}
	defer releaseCOM(unsafe.Pointer(qualifiers))
	values, present, err := qualifierStrings(qualifiers, "Values")
	if err != nil {
		return "", err
	}
	if !present {
		return "", errors.New("firewall enumeration Values qualifier is missing")
	}
	valueMap, explicit, err := qualifierStrings(qualifiers, "ValueMap")
	if err != nil {
		return "", err
	}
	index := -1
	if explicit {
		if len(values) != len(valueMap) {
			return "", errors.New("firewall ValueMap/Values lengths differ")
		}
		for i, text := range valueMap {
			n, e := strconv.ParseUint(strings.TrimSpace(text), 0, 32)
			if e == nil && n == uint64(number) {
				if index >= 0 {
					return "", errors.New("ambiguous firewall enumeration mapping")
				}
				index = i
			}
		}
	} else if uint64(number) < uint64(len(values)) {
		// Documented Values-only qualifiers use zero-based ordinal mapping.
		index = int(number)
	}
	if index < 0 {
		return "", errors.New("firewall enumeration value is not mapped by provider metadata")
	}
	label := strings.ReplaceAll(strings.TrimSpace(values[index]), " ", "")
	for _, canonical := range []string{"True", "False", "Block", "Allow", "NotConfigured"} {
		if strings.EqualFold(label, canonical) {
			return canonical, nil
		}
	}
	return "", errors.New("firewall enumeration label is unknown or localized")
}

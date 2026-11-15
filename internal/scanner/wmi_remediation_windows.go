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
)

type contextVtbl struct {
	unknownVtbl
	Clone, GetNames, BeginEnumeration, Next, EndEnumeration, SetValue uintptr
}
type comContext struct{ Vtbl *contextVtbl }

func partialWMIContext(property string) (*comContext, error) {
	clsid := syscall.GUID{Data1: 0x674b6698, Data2: 0xee92, Data3: 0x11d0, Data4: [8]byte{0xad, 0x71, 0, 0xc0, 0x4f, 0xd8, 0xfd, 0xff}}
	iid := syscall.GUID{Data1: 0x44aca674, Data2: 0xe8fc, Data3: 0x11d0, Data4: [8]byte{0xa0, 0x7c, 0, 0xc0, 0x4f, 0xb6, 0x88, 0x20}}
	var ctx *comContext
	result, _, _ := createCOM.Call(uintptr(unsafe.Pointer(&clsid)), 0, 1, uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&ctx)))
	if err := hresult("CoCreateInstance(IWbemContext)", result); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, errors.New("partial-update context is unavailable")
	}
	fail := func(err error) (*comContext, error) { releaseCOM(unsafe.Pointer(ctx)); return nil, err }
	set := func(name string, value variant) error {
		wide, err := syscall.UTF16PtrFromString(name)
		if err != nil {
			return err
		}
		result, _, _ := syscall.SyscallN(ctx.Vtbl.SetValue, uintptr(unsafe.Pointer(ctx)), uintptr(unsafe.Pointer(wide)), 0, uintptr(unsafe.Pointer(&value)))
		runtime.KeepAlive(wide)
		runtime.KeepAlive(value)
		return hresult("IWbemContext.SetValue", result)
	}
	for _, name := range []string{"__PUT_EXTENSIONS", "__PUT_EXT_CLIENT_REQUEST", "__PUT_EXT_ATOMIC"} {
		if err := set(name, variant{Kind: 11, Data: [2]uintptr{0xffff}}); err != nil {
			return fail(err)
		}
	}
	array, _, _ := arrayCreateVector.Call(8, 0, 1)
	if array == 0 {
		return fail(errors.New("cannot allocate partial-update property array"))
	}
	defer arrayDestroy.Call(array)
	text, err := bstr(property)
	if err != nil {
		return fail(err)
	}
	defer freeBSTR.Call(text)
	var index int32
	// VT_BSTR is passed directly, without a further pointer indirection.
	result, _, _ = arrayPutElement.Call(array, uintptr(unsafe.Pointer(&index)), text)
	if err := hresult("SafeArrayPutElement", result); err != nil {
		return fail(err)
	}
	if err := set("__PUT_EXT_PROPERTIES", variant{Kind: 0x2008, Data: [2]uintptr{array}}); err != nil {
		return fail(err)
	}
	return ctx, nil
}

func rawWMISnapshot(plan RegistryPlan, object *comClass, value variant, cim uint32) (RegistrySnapshot, error) {
	var scalar uint64
	switch value.Kind {
	case 11:
		b := int16(value.Data[0])
		if b != 0 && b != -1 {
			return RegistrySnapshot{}, errors.New("invalid native WMI Boolean")
		}
		if b == -1 {
			scalar = 1
		}
	case 17:
		scalar = uint64(uint8(value.Data[0]))
	case 18:
		scalar = uint64(uint16(value.Data[0]))
	case 3, 19:
		scalar = uint64(uint32(value.Data[0]))
	default:
		return RegistrySnapshot{}, errors.New("WMI mutation requires a reviewed non-null scalar type")
	}
	property, err := syscall.UTF16PtrFromString("__RELPATH")
	if err != nil {
		return RegistrySnapshot{}, err
	}
	var path variant
	result, _, _ := syscall.SyscallN(object.Vtbl.Get, uintptr(unsafe.Pointer(object)), uintptr(unsafe.Pointer(property)), 0, uintptr(unsafe.Pointer(&path)), 0, 0)
	if err := hresult("IWbemClassObject.Get(identity)", result); err != nil {
		return RegistrySnapshot{}, err
	}
	defer clearVariant.Call(uintptr(unsafe.Pointer(&path)))
	if path.Kind != 8 {
		return RegistrySnapshot{}, errors.New("WMI instance identity is unavailable")
	}
	identity, err := readBSTR(path.Data[0])
	check := wmiChecks[plan.Name]
	if err != nil || !(strings.HasPrefix(identity, check.Class+".") || identity == check.Class+"=@") {
		return RegistrySnapshot{}, errors.New("WMI relative instance identity requires review")
	}
	fingerprint := sha256.Sum256([]byte(check.Namespace + "\x00" + identity))
	data := binary.LittleEndian.AppendUint32(nil, uint32(value.Kind))
	data = binary.LittleEndian.AppendUint32(data, cim)
	data = binary.LittleEndian.AppendUint64(data, scalar)
	data = append(data, fingerprint[:]...)
	snapshot := RegistrySnapshot{RuleID: plan.RuleID, Exists: true, Kind: wmiSnapshotKind, Data: data}
	if !ValidSnapshot(plan, snapshot) {
		return RegistrySnapshot{}, errors.New("WMI scalar type or identity is outside the reviewed snapshot shape")
	}
	return snapshot, nil
}

func snapshotWMI(plan RegistryPlan) (snapshot RegistrySnapshot, err error) {
	_, err = withWMIScalar(plan.Name, func(_ *comServices, object *comClass, value variant, cim uint32) error {
		var err error
		snapshot, err = rawWMISnapshot(plan, object, value, cim)
		return err
	})
	return snapshot, err
}

func replaceWMI(ctx context.Context, plan RegistryPlan, want, expected RegistrySnapshot) error {
	if !bytes.Equal(want.Data[:8], expected.Data[:8]) || !bytes.Equal(want.Data[16:], expected.Data[16:]) {
		return errors.New("WMI replacement must retain the original type and instance identity")
	}
	_, err := withWMIScalar(plan.Name, func(services *comServices, object *comClass, value variant, cim uint32) error {
		current, err := rawWMISnapshot(plan, object, value, cim)
		if err != nil || !SameSnapshot(current, expected) {
			return errors.New("WMI selected property or instance changed externally")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		property := wmiChecks[plan.Name].Property
		partial, err := partialWMIContext(property)
		if err != nil {
			return err
		}
		defer releaseCOM(unsafe.Pointer(partial))
		wide, err := syscall.UTF16PtrFromString(property)
		if err != nil {
			return err
		}
		number := binary.LittleEndian.Uint64(want.Data[8:])
		updated := variant{Kind: value.Kind, Data: [2]uintptr{uintptr(number)}}
		if value.Kind == 11 && number == 1 {
			updated.Data[0] = 0xffff
		}
		result, _, _ := syscall.SyscallN(object.Vtbl.Put, uintptr(unsafe.Pointer(object)), uintptr(unsafe.Pointer(wide)), 0, uintptr(unsafe.Pointer(&updated)), uintptr(cim))
		runtime.KeepAlive(wide)
		runtime.KeepAlive(updated)
		if err := hresult("IWbemClassObject.Put(selected property)", result); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// WBEM_FLAG_UPDATE_ONLY. Mandatory extensions forbid whole-instance fallback.
		result, _, _ = syscall.SyscallN(services.Vtbl.PutInstance, uintptr(unsafe.Pointer(services)), uintptr(unsafe.Pointer(object)), 1, uintptr(unsafe.Pointer(partial)), 0)
		return hresult("IWbemServices.PutInstance(partial update required)", result)
	})
	if err != nil {
		return err
	}
	after, err := snapshotWMI(plan)
	if err != nil || !SameSnapshot(after, want) {
		return errors.New("WMI selected-property recheck did not match requested state")
	}
	return nil
}

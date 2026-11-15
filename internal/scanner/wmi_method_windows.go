//go:build windows

package scanner

import (
	"context"
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

// Method names, classes and the single selected input are compiled. No remote
// task can supply a method, namespace, object path or additional parameter.
func setCompiledWMIScalar(ctx context.Context, services *comServices, plan RegistryPlan, value variant, cim uint32) error {
	check, known := wmiChecks[plan.Name]
	if !known {
		return errors.New("WMI method target is outside the compiled allowlist")
	}
	method := "SetConfiguration"
	if check.Class == "MSFT_MpPreference" {
		method = "Set"
	} else if check.Class != "MSFT_SmbServerConfiguration" && check.Class != "MSFT_SmbClientConfiguration" {
		return errors.New("WMI class has no reviewed scalar setter")
	}
	classPath, err := bstr(check.Class)
	if err != nil {
		return err
	}
	defer freeBSTR.Call(classPath)
	var definition *comClass
	result, _, _ := syscall.SyscallN(services.Vtbl.GetObject, uintptr(unsafe.Pointer(services)), classPath, 0, 0, uintptr(unsafe.Pointer(&definition)), 0)
	if err := hresult("IWbemServices.GetObject(setter class)", result); err != nil {
		return err
	}
	if definition == nil {
		return errors.New("WMI setter class is unavailable")
	}
	defer releaseCOM(unsafe.Pointer(definition))
	wideMethod, err := syscall.UTF16PtrFromString(method)
	if err != nil {
		return err
	}
	var signature *comClass
	result, _, _ = syscall.SyscallN(definition.Vtbl.GetMethod, uintptr(unsafe.Pointer(definition)), uintptr(unsafe.Pointer(wideMethod)), 0, uintptr(unsafe.Pointer(&signature)), 0)
	runtime.KeepAlive(wideMethod)
	if err := hresult("IWbemClassObject.GetMethod(compiled setter)", result); err != nil {
		return err
	}
	if signature == nil {
		return errors.New("WMI compiled setter has no input signature")
	}
	defer releaseCOM(unsafe.Pointer(signature))
	var input *comClass
	result, _, _ = syscall.SyscallN(signature.Vtbl.SpawnInstance, uintptr(unsafe.Pointer(signature)), 0, uintptr(unsafe.Pointer(&input)))
	if err := hresult("IWbemClassObject.SpawnInstance(setter input)", result); err != nil {
		return err
	}
	if input == nil {
		return errors.New("WMI setter input is unavailable")
	}
	defer releaseCOM(unsafe.Pointer(input))
	property, err := syscall.UTF16PtrFromString(check.Property)
	if err != nil {
		return err
	}
	var original variant
	var parameterType uint32
	result, _, _ = syscall.SyscallN(input.Vtbl.Get, uintptr(unsafe.Pointer(input)), uintptr(unsafe.Pointer(property)), 0, uintptr(unsafe.Pointer(&original)), uintptr(unsafe.Pointer(&parameterType)), 0)
	if err := hresult("IWbemClassObject.Get(selected setter parameter)", result); err != nil {
		return err
	}
	defer clearVariant.Call(uintptr(unsafe.Pointer(&original)))
	if parameterType != cim {
		return errors.New("WMI setter parameter type differs from the selected property")
	}
	result, _, _ = syscall.SyscallN(input.Vtbl.Put, uintptr(unsafe.Pointer(input)), uintptr(unsafe.Pointer(property)), 0, uintptr(unsafe.Pointer(&value)), uintptr(cim))
	runtime.KeepAlive(property)
	runtime.KeepAlive(value)
	if err := hresult("IWbemClassObject.Put(selected setter parameter)", result); err != nil {
		return err
	}
	methodName, err := bstr(method)
	if err != nil {
		return err
	}
	defer freeBSTR.Call(methodName)
	if err := ctx.Err(); err != nil {
		return err
	}
	var output *comClass
	result, _, _ = syscall.SyscallN(services.Vtbl.ExecMethod, uintptr(unsafe.Pointer(services)), classPath, methodName, 0, 0, uintptr(unsafe.Pointer(input)), uintptr(unsafe.Pointer(&output)), 0)
	if output != nil {
		defer releaseCOM(unsafe.Pointer(output))
	}
	if err := hresult("IWbemServices.ExecMethod(compiled scalar setter)", result); err != nil {
		return err
	}
	if output == nil {
		return errors.New("WMI setter returned no result")
	}
	returned, err := syscall.UTF16PtrFromString("ReturnValue")
	if err != nil {
		return err
	}
	var status variant
	result, _, _ = syscall.SyscallN(output.Vtbl.Get, uintptr(unsafe.Pointer(output)), uintptr(unsafe.Pointer(returned)), 0, uintptr(unsafe.Pointer(&status)), 0, 0)
	if err := hresult("IWbemClassObject.Get(setter status)", result); err != nil {
		return err
	}
	defer clearVariant.Call(uintptr(unsafe.Pointer(&status)))
	if (status.Kind != 3 && status.Kind != 19) || uint32(status.Data[0]) != 0 {
		return errors.New("WMI compiled scalar setter did not report success")
	}
	return nil
}

//go:build windows

package scanner

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"syscall"
)

func supportedOS() error { return nil }

func supportedBenchmark(benchmark string) error {
	const key = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	buildText, err := registryValue(key, "CurrentBuildNumber")
	if err != nil {
		return errors.New("cannot identify Windows build")
	}
	build, err := strconv.Atoi(buildText)
	if err != nil {
		return errors.New("invalid Windows build")
	}
	installation, err := registryValue(key, "InstallationType")
	if err != nil {
		return errors.New("cannot identify Windows installation type")
	}
	server := strings.Contains(strings.ToLower(installation), "server")
	matched := (benchmark == "windows-10-native-registry" && !server && build >= 10240 && build < 22000) ||
		(benchmark == "windows-11-native-registry" && !server && build >= 22000) ||
		(benchmark == "server-2022-native-registry" && server && build == 20348)
	if !matched {
		return errors.New("assigned benchmark is not applicable to this Windows build")
	}
	return nil
}

func registryValue(path, name string) (string, error) {
	kind, buf, err := registryRaw(path, name)
	if err != nil {
		return "", err
	}
	size := len(buf)
	switch kind {
	case syscall.REG_DWORD:
		if size != 4 {
			return "", errors.New("invalid DWORD size")
		}
		return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(buf)), 10), nil
	case syscall.REG_QWORD:
		if size != 8 {
			return "", errors.New("invalid QWORD size")
		}
		return strconv.FormatUint(binary.LittleEndian.Uint64(buf), 10), nil
	case syscall.REG_SZ:
		if size%2 != 0 {
			return "", errors.New("invalid UTF-16 size")
		}
		value := make([]uint16, size/2)
		for i := range value {
			value[i] = binary.LittleEndian.Uint16(buf[i*2:])
		}
		return syscall.UTF16ToString(value), nil
	default:
		return "", errors.New("unsupported registry value type")
	}
}

func anonymousPipes() (string, error) {
	kind, data, err := registryRaw(`SYSTEM\CurrentControlSet\Services\LanManServer\Parameters`, "NullSessionPipes")
	if err == syscall.ERROR_FILE_NOT_FOUND || err == syscall.ERROR_PATH_NOT_FOUND {
		return "none", nil
	}
	if err != nil {
		return "", err
	}
	if kind != syscall.REG_MULTI_SZ || len(data)%2 != 0 {
		return "", errors.New("NullSessionPipes is not a UTF-16 string list")
	}
	for _, b := range data {
		if b != 0 {
			return "configured", nil
		}
	}
	return "none", nil
}

func registryRaw(path, name string) (uint32, []byte, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, nil, err
	}
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, nil, err
	}
	var key syscall.Handle
	// KEY_QUERY_VALUE | KEY_WOW64_64KEY, including for a 32-bit agent process.
	if err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, p, 0, 0x0001|0x0100, &key); err != nil {
		return 0, nil, err
	}
	defer syscall.RegCloseKey(key)
	var kind, size uint32
	if err = syscall.RegQueryValueEx(key, n, nil, &kind, nil, &size); err != nil {
		return 0, nil, err
	}
	if size > 65536 {
		return 0, nil, errors.New("registry value exceeds 64 KiB")
	}
	buf := make([]byte, size+2)
	if err = syscall.RegQueryValueEx(key, n, nil, &kind, &buf[0], &size); err != nil {
		return 0, nil, err
	}
	return kind, buf[:size], nil
}

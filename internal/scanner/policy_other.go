//go:build !windows

package scanner

func nativeValue(r Rule) (string, error) { return "", supportedOS() }

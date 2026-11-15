//go:build !windows

package scanner

import "errors"

func supportedOS() error                              { return errors.New("native Windows scanning requires Windows") }
func registryValue(path, name string) (string, error) { return "", supportedOS() }
func supportedBenchmark(benchmark string) error       { return supportedOS() }

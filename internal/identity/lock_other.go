//go:build !windows

package identity

import "errors"

func Lock(path string) (func(), error) { return nil, errors.New("Windows agent requires Windows") }

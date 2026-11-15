//go:build !windows

package identity

import "errors"

func crypt(data []byte, encrypt bool) ([]byte, error) {
	return nil, errors.New("DPAPI identity storage requires Windows")
}

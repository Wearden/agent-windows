//go:build !windows

package identity

import "errors"

func commitNewIdentity(from, to string) error {
	return errors.New("Windows identity storage requires Windows")
}

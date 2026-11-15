//go:build !windows

package actions

import "errors"

func commit(from, to string, replace bool) error {
	return errors.New("Windows task storage requires Windows")
}
func privateDirectory(path string) error { return errors.New("Windows task storage requires Windows") }

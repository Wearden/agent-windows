//go:build !windows

package main

import (
	"context"
	"errors"
)

func serviceCLI(ctx context.Context, args []string) error {
	return errors.New("SCM lifecycle requires Windows")
}
func hostService() error { return errors.New("SCM hosting requires Windows") }

//go:build !windows

package actions

import (
	"context"
	"errors"
)

func uptimeMillis() uint64 { return 0 }

func lockTask(ctx context.Context, root, id string) (func(), error) {
	return nil, errors.New("Windows task locking requires Windows")
}
func startHelper(executable, root, id, nonce string) (int, error) {
	return 0, errors.New("Windows recovery helper requires Windows")
}
func helperAlive(pid int) error { return errors.New("Windows recovery helper requires Windows") }
func trustedExecutable(path string) error {
	return errors.New("Windows recovery helper requires Windows")
}
func trustedState(root string) error { return errors.New("Windows recovery helper requires Windows") }

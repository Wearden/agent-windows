//go:build !windows

package scanner

import "context"

func ApplyPrecondition(plan RegistryPlan) error { return supportedOS() }

func Snapshot(plan RegistryPlan) (RegistrySnapshot, error)             { return RegistrySnapshot{}, supportedOS() }
func Replace(plan RegistryPlan, want, expected RegistrySnapshot) error { return supportedOS() }
func ReplaceContext(ctx context.Context, plan RegistryPlan, want, expected RegistrySnapshot) error {
	return supportedOS()
}

func lsaTargetMode() (uint32, error) { return 0, supportedOS() }

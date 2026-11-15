//go:build !windows

package scanner

func Snapshot(plan RegistryPlan) (RegistrySnapshot, error)             { return RegistrySnapshot{}, supportedOS() }
func Replace(plan RegistryPlan, want, expected RegistrySnapshot) error { return supportedOS() }

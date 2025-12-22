//go:build linux
// +build linux

package common

import (
	"io"
	"os"
	"os/exec"
	"runtime"
)

// IsRoot returns true if the current process has root privileges.
func IsRoot() bool {
	return os.Geteuid() == 0
}

// RunPrivileged executes a command, prepending sudo on Linux when not root.
// Binaries are expected to be started with sudo/root; this is a best-effort fallback.
func RunPrivileged(name string, args ...string) error {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return exec.Command("sudo", append([]string{name}, args...)...).Run()
	}
	return exec.Command(name, args...).Run()
}

// RunPrivilegedSilent runs a command discarding stdout/stderr, with sudo on Linux when needed.
func RunPrivilegedSilent(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		cmd = exec.Command("sudo", append([]string{name}, args...)...)
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

// RunPrivilegedOutput runs a command and returns stdout, with sudo on Linux when needed.
func RunPrivilegedOutput(name string, args ...string) ([]byte, error) {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return exec.Command("sudo", append([]string{name}, args...)...).Output()
	}
	return exec.Command(name, args...).Output()
}

// RunPrivilegedCombined runs a command and returns combined stdout/stderr, with sudo on Linux when needed.
func RunPrivilegedCombined(name string, args ...string) ([]byte, error) {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return exec.Command("sudo", append([]string{name}, args...)...).CombinedOutput()
	}
	return exec.Command(name, args...).CombinedOutput()
}

package common

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// IsRoot returns true if the current process has root privileges.
func IsRoot() bool {
	return os.Geteuid() == 0
}

// NeedsElevation returns true if we're on Linux and not root.
func NeedsElevation() bool {
	return runtime.GOOS == "linux" && !IsRoot()
}

// RelaunchWithPkexec re-executes the current process with pkexec for graphical sudo prompt.
// This will show a polkit authentication dialog on Linux desktop systems.
// Returns error if pkexec is not available or user cancels.
// extraArgs are appended to the command line (use for passing current config).
func RelaunchWithPkexec(extraArgs ...string) error {
	if !NeedsElevation() {
		return nil // already root
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable: %w", err)
	}
	// Build args: original args + extra args
	args := append([]string{exe}, os.Args[1:]...)
	args = append(args, extraArgs...)

	// Try pkexec first (shows GUI dialog)
	pkexec, err := exec.LookPath("pkexec")
	if err == nil {
		return syscall.Exec(pkexec, append([]string{"pkexec"}, args...), os.Environ())
	}
	// Fall back to sudo (terminal prompt)
	sudo, err := exec.LookPath("sudo")
	if err == nil {
		return syscall.Exec(sudo, append([]string{"sudo"}, args...), os.Environ())
	}
	return fmt.Errorf("neither pkexec nor sudo available; please run as root")
}

// RunPrivileged executes a command, automatically elevating with sudo on Linux when not root.
// It is best-effort; if sudo is unavailable or the user denies the prompt, the error is returned.
func RunPrivileged(name string, args ...string) error {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return exec.Command("sudo", append([]string{name}, args...)...).Run()
	}
	return exec.Command(name, args...).Run()
}

// RunPrivilegedOutput runs a command and returns stdout, elevating with sudo when needed.
func RunPrivilegedOutput(name string, args ...string) ([]byte, error) {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return exec.Command("sudo", append([]string{name}, args...)...).Output()
	}
	return exec.Command(name, args...).Output()
}

// RunPrivilegedCombined runs a command and returns combined stdout/stderr, with sudo when needed.
func RunPrivilegedCombined(name string, args ...string) ([]byte, error) {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return exec.Command("sudo", append([]string{name}, args...)...).CombinedOutput()
	}
	return exec.Command(name, args...).CombinedOutput()
}

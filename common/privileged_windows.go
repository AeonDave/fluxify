//go:build windows
// +build windows

package common

import (
	"io"
	"os/exec"

	"golang.org/x/sys/windows"
)

// Windows admin detection using token elevation.
func IsRoot() bool {
	var t windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &t)
	if err != nil {
		return false
	}
	defer t.Close()
	return t.IsElevated()
}

// RunPrivileged executes a command as-is; caller should ensure elevation.
func RunPrivileged(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// RunPrivilegedSilent executes a command discarding stdout/stderr.
func RunPrivilegedSilent(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

// RunPrivilegedOutput executes a command and returns stdout.
func RunPrivilegedOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

// RunPrivilegedCombined executes a command and returns combined stdout/stderr.
func RunPrivilegedCombined(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

//go:build !windows

package main

// runWithTray is a no-op pass-through on platforms without a system tray
// integration; the client runs exactly as before.
func runWithTray(body func()) {
	body()
}

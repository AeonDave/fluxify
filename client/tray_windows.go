//go:build windows

package main

import (
	_ "embed"
	"fmt"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
)

//go:embed assets/fluxify.ico
var trayIconOn []byte

//go:embed assets/fluxify-off.ico
var trayIconOff []byte

// runWithTray hosts the client entrypoint inside the systray event loop so
// the notification-area icon lives for the whole process lifetime. When body
// returns (Ctrl-C, TUI quit, tray Quit) the loop is torn down with it.
func runWithTray(body func()) {
	onReady := func() {
		systray.SetIcon(trayIconOff)
		systray.SetTooltip("Fluxify — disconnected")

		statusItem := systray.AddMenuItem("Disconnected", "Bonding status")
		statusItem.Disable()
		toggleItem := systray.AddMenuItem("Hide window", "Show or hide the console window")
		systray.AddSeparator()
		quitItem := systray.AddMenuItem("Quit", "Stop Fluxify and restore routes")

		// Double-click on the icon brings the console back.
		systray.SetOnTapped(func() {
			if showConsole(true) {
				toggleItem.SetTitle("Hide window")
			}
		})

		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			connected := false
			lastStatus := ""
			for {
				select {
				case <-toggleItem.ClickedCh:
					if showConsole(!consoleVisible) {
						toggleItem.SetTitle("Hide window")
					} else {
						toggleItem.SetTitle("Show window")
					}
				case <-quitItem.ClickedCh:
					quitItem.Disable()
					statusItem.SetTitle("Stopping...")
					requestAppShutdown()
				case <-t.C:
					alive, active, total := trayStatusSnapshot()
					status := "Disconnected"
					if alive {
						status = fmt.Sprintf("Connected (%d/%d paths)", active, total)
					}
					if status != lastStatus {
						lastStatus = status
						statusItem.SetTitle(status)
						systray.SetTooltip("Fluxify — " + status)
					}
					if alive != connected {
						connected = alive
						if alive {
							systray.SetIcon(trayIconOn)
						} else {
							systray.SetIcon(trayIconOff)
						}
					}
				}
			}
		}()

		go func() {
			body()
			systray.Quit()
		}()
	}
	systray.Run(onReady, func() {})
}

var (
	user32              = windows.NewLazySystemDLL("user32.dll")
	kernel32            = windows.NewLazySystemDLL("kernel32.dll")
	procShowWindowAsync = user32.NewProc("ShowWindowAsync")
	procSetForeground   = user32.NewProc("SetForegroundWindow")
	procGetConsoleWnd   = kernel32.NewProc("GetConsoleWindow")

	consoleVisible = true
)

const (
	swHide = 0
	swShow = 5
)

// showConsole shows or hides the console window and reports the resulting
// visibility. With no attached console (e.g. a future GUI host) it is a no-op
// that always reports "visible".
func showConsole(visible bool) bool {
	hwnd, _, _ := procGetConsoleWnd.Call()
	if hwnd == 0 {
		return true
	}
	if visible {
		_, _, _ = procShowWindowAsync.Call(hwnd, swShow)
		_, _, _ = procSetForeground.Call(hwnd)
	} else {
		_, _, _ = procShowWindowAsync.Call(hwnd, swHide)
	}
	consoleVisible = visible
	return consoleVisible
}

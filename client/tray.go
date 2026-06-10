package main

import (
	"sync/atomic"
)

// The tray hub decouples the (Windows-only) system-tray icon from the run
// modes: whichever flow is active registers a graceful-shutdown callback,
// and the bonding state machine publishes its status here.

var trayShutdownFn atomic.Value // func()

// registerTrayShutdown installs the callback the tray's Quit item invokes.
// The callback must trigger the same teardown as Ctrl-C / the TUI Quit.
func registerTrayShutdown(f func()) {
	trayShutdownFn.Store(f)
}

func requestAppShutdown() {
	if f, ok := trayShutdownFn.Load().(func()); ok && f != nil {
		f()
	}
}

var (
	trayServerAlive atomic.Bool
	trayActivePaths atomic.Int32
	trayTotalPaths  atomic.Int32
)

func trayPublishStatus(alive bool, active, total int) {
	trayServerAlive.Store(alive)
	trayActivePaths.Store(int32(active))
	trayTotalPaths.Store(int32(total))
}

func trayStatusSnapshot() (alive bool, active, total int) {
	return trayServerAlive.Load(), int(trayActivePaths.Load()), int(trayTotalPaths.Load())
}

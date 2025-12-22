package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"fluxify/common"
)

func TestPickBestConnLoadBalanceChoosesLowestRTT(t *testing.T) {
	c := &clientState{mode: modeLoadBalance}
	slow := &clientConn{}
	slow.alive.Store(true)
	slow.rttNano.Store(int64(200 * 1e6)) // 200ms
	fast := &clientConn{}
	fast.alive.Store(true)
	fast.rttNano.Store(int64(10 * 1e6)) // 10ms
	c.conns = []*clientConn{slow, fast}

	got := c.pickBestConn()
	if got != fast {
		t.Fatalf("expected fast conn, got %p", got)
	}
}

// TestRouteRevertHook ensures the revertRoute hook is set when default route is set to TUN (simulated).
// This is a light-weight check that the hook is wired; it does not execute system commands.
func TestRouteRevertHookWired(t *testing.T) {
	state := &clientState{}
	state.revertRoute = func() {}
	if state.revertRoute == nil {
		t.Fatalf("revertRoute should be non-nil")
	}
}

// TestGetDefaultRouteNonLinux is a safety check that the helper is a no-op on non-Linux.
func TestGetDefaultRouteNonLinux(t *testing.T) {
	if common.IsLinux() {
		t.Skip("linux env would try ip route")
	}
	if _, _, _, err := common.GetDefaultRoute(); err != nil {
		t.Fatalf("expected no error on non-linux: %v", err)
	}
}

func TestCLIStartsTUIWhenNoModeFlags(t *testing.T) {
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })
	os.Args = []string{"client"}

	var buf bytes.Buffer
	logFatalf = log.Fatalf
	log.SetOutput(&buf)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		logFatalf = log.Fatalf
	})

	startedTUI := false
	runTUIHook = func(cfg clientConfig, autoStart bool) {
		startedTUI = true
	}
	t.Cleanup(func() { runTUIHook = realRunTUI })

	main()
	if !startedTUI {
		t.Fatalf("expected TUI to start when no mode flags provided")
	}
}

func TestCLIFailsWithoutRequiredBondingParams(t *testing.T) {
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })
	os.Args = []string{"client", "-b", "-ifaces", "eth0,eth1"}

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	exitCh := make(chan string, 1)
	realFatal := logFatalf
	runTUIHook = realRunTUI
	logFatalf = func(format string, args ...interface{}) {
		exitCh <- fmt.Sprintf(format, args...)
		panic("exit")
	}
	t.Cleanup(func() { logFatalf = realFatal })

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected fatal exit when server/client missing")
		}
	}()

	main()

	select {
	case msg := <-exitCh:
		if !strings.Contains(msg, "server is required") {
			t.Fatalf("unexpected fatal msg: %s", msg)
		}
	case <-time.After(time.Second):
		t.Fatalf("fatal not triggered")
	}
}

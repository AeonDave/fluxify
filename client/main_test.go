package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPickBestConnLoadBalanceChoosesLowestRTT(t *testing.T) {
	c := &clientState{mode: modeLoadBalance}
	slow := &clientConn{}
	slow.alive.Store(true)
	slow.rttNano.Store(int64(200 * time.Millisecond))
	fast := &clientConn{}
	fast.alive.Store(true)
	fast.rttNano.Store(int64(10 * time.Millisecond))
	c.conns = []*clientConn{slow, fast}

	got := c.pickBestConn()
	if got != fast {
		t.Fatalf("expected fast conn, got %p", got)
	}
}

func TestPickBestConnLoadBalanceTreatsZeroRTTAsPenalty(t *testing.T) {
	c := &clientState{mode: modeLoadBalance}
	unknown := &clientConn{}
	unknown.alive.Store(true)
	unknown.rttNano.Store(0)
	known := &clientConn{}
	known.alive.Store(true)
	known.rttNano.Store(int64(20 * time.Millisecond))
	c.conns = []*clientConn{unknown, known}

	got := c.pickBestConn()
	if got != known {
		t.Fatalf("expected known RTT conn, got %p", got)
	}
}

func TestPickBestConnLoadBalanceFallsBackWhenNoneAlive(t *testing.T) {
	c := &clientState{mode: modeLoadBalance}
	a := &clientConn{}
	b := &clientConn{}
	a.alive.Store(false)
	b.alive.Store(false)
	c.conns = []*clientConn{a, b}

	got := c.pickBestConn()
	if got != a {
		t.Fatalf("expected fallback to first conn, got %p", got)
	}
}

func TestPickBestConnBondingPrefersAlive(t *testing.T) {
	c := &clientState{mode: modeBonding}
	dead := &clientConn{}
	alive := &clientConn{}
	dead.alive.Store(false)
	alive.alive.Store(true)
	c.conns = []*clientConn{dead, alive}

	got := c.pickBestConn()
	if got == nil || !got.alive.Load() {
		t.Fatalf("expected an alive conn, got %#v", got)
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
	runTUIHook = func(cfg clientConfig) {
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

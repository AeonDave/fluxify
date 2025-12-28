//go:build linux
// +build linux

package main

import (
	"errors"
	"reflect"
	"testing"
)

type fakeRunner struct {
	// calls: [][name,args]
	calls [][]string
	// If set, treat -C as success.
	exists map[string]bool
}

func (f *fakeRunner) Run(name string, args ...string) error {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	// emulate: if it's a check (-C) and rule exists, return nil
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-C" {
			key := name + " " + join(args)
			if f.exists != nil && f.exists[key] {
				return nil
			}
			return errors.New("not found")
		}
	}
	return nil
}

func join(args []string) string {
	// simple join for test keys
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}

func TestParseMSSClampFlag(t *testing.T) {
	for _, tc := range []struct {
		in   string
		mode mssClampMode
		fix  int
		ok   bool
	}{
		{"off", mssClampOff, 0, true},
		{"pmtu", mssClampPMTU, 0, true},
		{"fixed:1360", mssClampFixed, 1360, true},
		{"1360", mssClampFixed, 1360, true},
		{"fixed:10", mssClampOff, 0, false},
		{"blah", mssClampOff, 0, false},
	} {
		cfg, err := parseMSSClampFlag(tc.in)
		if tc.ok && err != nil {
			t.Fatalf("%q expected ok, got %v", tc.in, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%q expected err", tc.in)
		}
		if tc.ok {
			if cfg.mode != tc.mode || cfg.fixed != tc.fix {
				t.Fatalf("%q cfg mismatch: %+v", tc.in, cfg)
			}
		}
	}
}

func TestEnsureMSSClampRules_IdempotentCheckThenAdd(t *testing.T) {
	r := &fakeRunner{}
	cfg := mssClampConfig{mode: mssClampFixed, fixed: 1360}
	err := ensureMSSClampRules(r, "tun0", cfg)
	if err != nil {
		t.Fatalf("ensureMSSClampRules: %v", err)
	}
	// Expect for each tool: 2 checks + 2 adds (POSTROUTING+FORWARD)
	// Total 8 calls.
	if len(r.calls) != 8 {
		t.Fatalf("expected 8 calls, got %d", len(r.calls))
	}
	// Spot-check first call is iptables check
	if r.calls[0][0] != "iptables" {
		t.Fatalf("expected iptables first, got %v", r.calls[0])
	}
	if !reflect.DeepEqual(r.calls[0][1:4], []string{"-t", "mangle", "-C"}) {
		t.Fatalf("expected -t mangle -C, got %v", r.calls[0])
	}
}

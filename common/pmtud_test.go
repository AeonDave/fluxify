package common

import (
	"testing"
	"time"
)

func TestSuggestSmallerMTU(t *testing.T) {
	tests := []struct {
		current int
		want    int
	}{
		{1400, 1350},
		{1350, 1300},
		{1300, 1280},
		{1280, 1200},
		{1200, 1280}, // min MTU
		{1100, 1280}, // min MTU
	}

	for _, tt := range tests {
		got := suggestSmallerMTU(tt.current)
		if got != tt.want {
			t.Errorf("suggestSmallerMTU(%d) = %d, want %d", tt.current, got, tt.want)
		}
	}
}

func TestParseRTTFromPing(t *testing.T) {
	tests := []struct {
		output string
		want   time.Duration
	}{
		{"time=10.5 ms", 10500 * time.Microsecond},
		{"time=1 ms", 1 * time.Millisecond},
		{"time<1ms", 1 * time.Millisecond},
		{"Reply from 1.2.3.4: time=5ms TTL=64", 5 * time.Millisecond},
		{"no rtt info here", 0},
		{"", 0},
	}

	for _, tt := range tests {
		got := parseRTTFromPing(tt.output)
		if got != tt.want {
			t.Errorf("parseRTTFromPing(%q) = %v, want %v", tt.output, got, tt.want)
		}
	}
}

func TestFormatPMTUDResult(t *testing.T) {
	// Test successful result
	successResult := PMTUDResult{
		Success:   true,
		TestedMTU: 1400,
		RTT:       50 * time.Millisecond,
		IPv6:      false,
	}
	s := FormatPMTUDResult(successResult)
	if s == "" {
		t.Error("FormatPMTUDResult returned empty string for success case")
	}

	// Test failed result with suggestion
	failResult := PMTUDResult{
		Success:    false,
		TestedMTU:  1400,
		SuggestMTU: 1350,
		Error:      "packet too big",
	}
	s = FormatPMTUDResult(failResult)
	if s == "" {
		t.Error("FormatPMTUDResult returned empty string for fail case")
	}
}

func TestDefaultProbeMTUs(t *testing.T) {
	// Verify MTUs are in decreasing order
	for i := 1; i < len(DefaultProbeMTUs); i++ {
		if DefaultProbeMTUs[i] >= DefaultProbeMTUs[i-1] {
			t.Errorf("DefaultProbeMTUs not in decreasing order at index %d: %d >= %d",
				i, DefaultProbeMTUs[i], DefaultProbeMTUs[i-1])
		}
	}

	// Verify first MTU matches common.MTU
	if DefaultProbeMTUs[0] != MTU {
		t.Errorf("DefaultProbeMTUs[0] = %d, want %d (common.MTU)", DefaultProbeMTUs[0], MTU)
	}
}

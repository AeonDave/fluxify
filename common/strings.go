package common

import "strings"

// SplitCSV splits a comma-separated string into trimmed, non-empty parts.
// Returns nil if the input string is empty or contains only whitespace.
func SplitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

package main

import (
	"log"
	"runtime/debug"
)

var verboseLevel int

// setVerboseLoggingLevel controls verbosity.
// 0 = default
// 1 = -v (useful lifecycle logs)
// 2 = -vv (very verbose, includes per-packet and repeated scan logs)
func setVerboseLoggingLevel(level int) {
	if level < 0 {
		level = 0
	}
	if level > 2 {
		level = 2
	}
	verboseLevel = level
}

// Back-compat for existing call sites/tests.
func setVerboseLogging(enabled bool) {
	if enabled {
		setVerboseLoggingLevel(1)
		return
	}
	setVerboseLoggingLevel(0)
}

func verboseEnabled() bool {
	return verboseLevel >= 1
}

func veryVerboseEnabled() bool {
	return verboseLevel >= 2
}

func vlogf(format string, args ...any) {
	if verboseEnabled() {
		log.Printf(format, args...)
	}
}

func vvlogf(format string, args ...any) {
	if veryVerboseEnabled() {
		log.Printf(format, args...)
	}
}

func logBuildProvenance() {
	if !verboseEnabled() {
		return
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok || bi == nil {
		log.Printf("build: no build info")
		return
	}

	log.Printf("build: go=%s", bi.GoVersion)
	if bi.Main.Path != "" {
		log.Printf("build: main=%s %s", bi.Main.Path, bi.Main.Version)
	}

	const mpquic = "github.com/AeonDave/mp-quic-go"
	for _, dep := range bi.Deps {
		if dep == nil {
			continue
		}
		if dep.Path != mpquic {
			continue
		}
		if dep.Replace != nil {
			log.Printf("build: dep=%s %s (replace=%s %s)", dep.Path, dep.Version, dep.Replace.Path, dep.Replace.Version)
		} else {
			log.Printf("build: dep=%s %s", dep.Path, dep.Version)
		}
		return
	}

	log.Printf("build: dep=%s (not found in build info)", mpquic)
}

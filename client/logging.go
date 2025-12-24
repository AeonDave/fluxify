package main

import "log"

var verboseLogging bool

func setVerboseLogging(enabled bool) {
	verboseLogging = enabled
}

func vlogf(format string, args ...any) {
	if verboseLogging {
		log.Printf(format, args...)
	}
}

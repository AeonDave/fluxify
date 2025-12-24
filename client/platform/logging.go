package platform

import "log"

var verboseLogging bool

// SetVerbose enables or disables verbose platform logging.
func SetVerbose(enabled bool) {
	verboseLogging = enabled
}

func vlogf(format string, args ...any) {
	if verboseLogging {
		log.Printf(format, args...)
	}
}

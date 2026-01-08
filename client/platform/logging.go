package platform

import "log"

var verboseLevel int

// SetVerbose enables or disables verbose platform logging.
func SetVerbose(enabled bool) {
	if enabled {
		SetVerboseLevel(1)
		return
	}
	SetVerboseLevel(0)
}

// SetVerboseLevel controls platform verbosity.
// 0 = default
// 1 = -v
// 2 = -vv
func SetVerboseLevel(level int) {
	if level < 0 {
		level = 0
	}
	if level > 2 {
		level = 2
	}
	verboseLevel = level
}

func vlogf(format string, args ...any) {
	if verboseLevel >= 1 {
		log.Printf(format, args...)
	}
}

func vvlogf(format string, args ...any) {
	if verboseLevel >= 2 {
		log.Printf(format, args...)
	}
}

//go:build windows && arm64
// +build windows,arm64

package platform

import _ "embed"

//go:embed wintun/arm64/wintun.dll
var wintunDLL []byte

func embeddedWintunDLL() []byte {
	return wintunDLL
}

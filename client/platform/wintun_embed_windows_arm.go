//go:build windows && arm
// +build windows,arm

package platform

import _ "embed"

//go:embed wintun/arm/wintun.dll
var wintunDLL []byte

func embeddedWintunDLL() []byte {
	return wintunDLL
}

//go:build windows && 386
// +build windows,386

package platform

import _ "embed"

//go:embed wintun/x86/wintun.dll
var wintunDLL []byte

func embeddedWintunDLL() []byte {
	return wintunDLL
}

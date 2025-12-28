//go:build !windows
// +build !windows

package platform

import "github.com/songgao/water"

func CreateTunDevice() (TunDevice, error) {
	conf := water.Config{DeviceType: water.TUN}
	return water.New(conf)
}

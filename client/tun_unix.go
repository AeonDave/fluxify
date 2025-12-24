//go:build !windows
// +build !windows

package main

import "github.com/songgao/water"

func createTunDevice() (tunDevice, error) {
	conf := water.Config{DeviceType: water.TUN}
	return water.New(conf)
}

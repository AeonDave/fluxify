//go:build windows
// +build windows

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

	"fluxify/common"
)

type wintunDevice struct {
	dev  tun.Device
	name string
}

var wintunExtractOnce sync.Once
var wintunExtractErr error

func CreateTunDevice() (TunDevice, error) {
	if err := ensureWintunDLL(); err != nil {
		return nil, err
	}
	dev, err := tun.CreateTUN("Fluxify", common.MTU)
	if err != nil {
		return nil, err
	}
	name, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	return &wintunDevice{dev: dev, name: name}, nil
}

func ensureWintunDLL() error {
	wintunExtractOnce.Do(func() {
		dll := embeddedWintunDLL()
		if len(dll) == 0 {
			wintunExtractErr = fmt.Errorf("wintun.dll not embedded for %s/%s", runtime.GOOS, runtime.GOARCH)
			return
		}
		exe, err := os.Executable()
		if err != nil {
			wintunExtractErr = err
			return
		}
		dst := filepath.Join(filepath.Dir(exe), "wintun.dll")
		if info, err := os.Stat(dst); err == nil {
			if info.Size() == int64(len(dll)) {
				return
			}
		}
		tmp := dst + ".tmp"
		if err := os.WriteFile(tmp, dll, 0o644); err != nil {
			wintunExtractErr = err
			return
		}
		if err := os.Rename(tmp, dst); err != nil {
			_ = os.Remove(tmp)
			wintunExtractErr = err
			return
		}
	})
	return wintunExtractErr
}

func (d *wintunDevice) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	bufs := [][]byte{p}
	sizes := []int{0}
	n, err := d.dev.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return sizes[0], nil
}

func (d *wintunDevice) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := d.dev.Write([][]byte{p}, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return len(p), nil
}

func (d *wintunDevice) Close() error {
	return d.dev.Close()
}

func (d *wintunDevice) Name() string {
	return d.name
}

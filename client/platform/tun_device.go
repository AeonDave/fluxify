package platform

import "io"

type TunDevice interface {
	io.ReadWriteCloser
	Name() string
}

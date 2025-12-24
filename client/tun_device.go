package main

import "io"

type tunDevice interface {
	io.ReadWriteCloser
	Name() string
}

package common

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

const (
	CompressionNone = 0
	CompressionGzip = 1
)

// CompressPayload compresses data with gzip (best speed) and returns the compressed bytes.
// Caller decides whether to use the compressed output based on size benefit.
func CompressPayload(data []byte) (out []byte, err error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	// Ensure the writer is always closed to avoid resource leaks; propagate Close error
	// only if no previous error occurred.
	defer func() {
		if e := zw.Close(); err == nil && e != nil {
			err = e
		}
	}()

	if _, err = zw.Write(data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecompressPayload inflates a gzip-compressed payload with an upper bound to avoid memory blowups.
// maxOut guards against maliciously large expansions.
func DecompressPayload(data []byte, maxOut int) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func(zr *gzip.Reader) {
		_ = zr.Close()
	}(zr)

	var buf bytes.Buffer
	// Limit the copy to maxOut bytes to avoid unbounded growth.
	if _, err := io.CopyN(&buf, zr, int64(maxOut)+1); err != nil && err != io.EOF {
		return nil, err
	}
	if buf.Len() > maxOut {
		return nil, fmt.Errorf("decompressed size exceeds limit: %d > %d", buf.Len(), maxOut)
	}
	return buf.Bytes(), nil
}

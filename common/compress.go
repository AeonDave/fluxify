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

// CompressPayloadInto compresses data with gzip into dst (if capacity allows) or allocates.
func CompressPayloadInto(dst []byte, data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(dst[:0])
	zw, err := gzip.NewWriterLevel(buf, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err = zw.Write(data); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CompressPayload compresses data with gzip (best speed) and returns the compressed bytes.
func CompressPayload(data []byte) (out []byte, err error) {
	return CompressPayloadInto(nil, data)
}

// DecompressPayloadInto inflates a gzip-compressed payload into dst.
func DecompressPayloadInto(dst []byte, data []byte, maxOut int) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func(zr *gzip.Reader) {
		_ = zr.Close()
	}(zr)

	buf := bytes.NewBuffer(dst[:0])
	if _, err := io.CopyN(buf, zr, int64(maxOut)+1); err != nil && err != io.EOF {
		return nil, err
	}
	if buf.Len() > maxOut {
		return nil, fmt.Errorf("decompressed size exceeds limit: %d > %d", buf.Len(), maxOut)
	}
	return buf.Bytes(), nil
}

// DecompressPayload inflates a gzip-compressed payload with an upper bound.
func DecompressPayload(data []byte, maxOut int) ([]byte, error) {
	return DecompressPayloadInto(nil, data, maxOut)
}

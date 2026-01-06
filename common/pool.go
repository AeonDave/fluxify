package common

import "sync"

const PoolBufSize = DataPlaneHdrSize + MaxPacketSize

var BufferPool = sync.Pool{
	New: func() interface{} {
		// Allocate a buffer large enough for dataplane header + payload
		return make([]byte, PoolBufSize)
	},
}

// GetBuffer returns a buffer from the pool.
// The returned slice has length=PoolBufSize and cap=PoolBufSize.
func GetBuffer() []byte {
	return BufferPool.Get().([]byte)
}

// PutBuffer returns a buffer to the pool.
func PutBuffer(b []byte) {
	if cap(b) < PoolBufSize {
		// discard if it was resized/sliced too small to be reused effectively
		return
	}
	// Reslice to full capacity before putting back
	b = b[:cap(b)]
	BufferPool.Put(b)
}

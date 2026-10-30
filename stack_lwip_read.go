//go:build with_lwip

package tun

import (
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ N.ReadWaiter           = (*lwipTCPConn)(nil)
	_ N.VectorisedReadWaiter = (*lwipTCPConn)(nil)
)

// Keep ordinary stream reads available with older Go bindings as well as the
// unchanged native ABI-2 libraries. The optional Go interface enables batching.
type lwipStreamBatchReader interface {
	ReadBatch(buffers [][]byte, sizes []int) (int, error)
}

func (c *lwipTCPConn) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	c.readOptions = options
	c.batchReader, _ = any(c.Conn).(lwipStreamBatchReader)
	c.readBatchSize = min(len(c.readBuffers), max(1, options.BatchSize))
	return false
}

func (c *lwipTCPConn) WaitReadBuffer() (*buf.Buffer, error) {
	buffer := c.readOptions.NewBuffer()
	n, err := c.Conn.Read(buffer.FreeBytes())
	if err != nil {
		buffer.Release()
		return nil, err
	}
	buffer.Extend(n)
	c.readOptions.PostReturn(buffer)
	return buffer, nil
}

func (c *lwipTCPConn) WaitReadBuffers() ([]*buf.Buffer, error) {
	// Two ABI-sized reads cover the native receive window. Bound temporary
	// storage and core-lock hold time independently of the caller's batch size.
	count := c.readBatchSize
	if c.batchReader == nil {
		buffer, err := c.WaitReadBuffer()
		if err != nil {
			return nil, err
		}
		c.readBuffers[0] = buffer
		return c.readBuffers[:1:1], nil
	}
	for i := range count {
		c.readBuffers[i] = c.readOptions.NewBuffer()
		c.readSlices[i] = c.readBuffers[i].FreeBytes()
	}
	n, err := c.batchReader.ReadBatch(c.readSlices[:count], c.readSizes[:count])
	// A bulk stream may become interactive. Use one buffer after a small read;
	// substantial reads restore batching. A GRO payload is smaller than 65535
	// by its IP/TCP headers, so requiring a completely full buffer would keep
	// an otherwise saturated upload permanently in single-buffer mode.
	if n == 1 && c.readSizes[0] < (len(c.readSlices[0])+1)/2 {
		c.readBatchSize = 1
	} else {
		c.readBatchSize = min(len(c.readBuffers), max(1, c.readOptions.BatchSize))
	}
	clear(c.readSlices[:])
	for i := n; i < count; i++ {
		c.readBuffers[i].Release()
		c.readBuffers[i] = nil
	}
	if err != nil {
		return nil, err
	}
	for i := range n {
		c.readBuffers[i].Extend(c.readSizes[i])
		c.readOptions.PostReturn(c.readBuffers[i])
	}
	return c.readBuffers[:n:n], nil
}

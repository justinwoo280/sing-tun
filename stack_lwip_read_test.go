//go:build with_lwip && (cgo || with_purego)

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

func TestLWIPTCPReadWaiterOwnership(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		h := &lwipGSOTestHandler{accepted: make(chan net.Conn, 1)}
		f := startLWIPGSOTest(t, h, false)
		f.packets <- lwipGSOTestTCP(v6, 100, 0, 2, nil)
		syn := lwipGSOTestNext(t, f.output, 6)
		parsed, _ := parseForwardPacket(syn)
		server := binary.BigEndian.Uint32(parsed.transport[4:]) + 1
		f.packets <- lwipGSOTestTCP(v6, 101, server, 16, nil)
		var conn net.Conn
		select {
		case conn = <-h.accepted:
		case <-time.After(time.Second):
			t.Fatal("accept timeout")
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(time.Second))
		c := conn.(*lwipTCPConn)
		options := N.ReadWaitOptions{FrontHeadroom: 32, RearHeadroom: 48, IncreaseBuffer: true, BatchSize: 8}
		if c.InitializeReadWaiter(options) {
			t.Fatal("unexpected extra-copy requirement")
		}
		seq := uint32(101)
		var want []byte
		for _, marker := range []byte{0x35, 0xc7} {
			data := bytes.Repeat([]byte{marker}, 60000)
			p := lwipGSOTestTCP(v6, seq, server, 16, data)
			if !normalizeLWIPGSO(p.packet, p.options) {
				t.Fatal("normalize")
			}
			if err := f.stack.engine.Input(p.packet); err != nil {
				t.Fatal(err)
			}
			seq += uint32(len(data))
			want = append(want, data...)
		}
		var got []byte
		for len(got) < len(want) {
			buffers, err := c.WaitReadBuffers()
			if err != nil {
				t.Fatal(err)
			}
			if c.batchReader != nil && len(got) == 0 && len(buffers) != 2 {
				t.Fatalf("batch=%d", len(buffers))
			}
			if c.batchReader == nil && len(buffers) != 1 {
				t.Fatal("older binding fallback")
			}
			for _, b := range buffers {
				if b.Start() != 32 || b.FreeLen() < 48 {
					t.Fatal("headroom/rear headroom lost")
				}
				got = append(got, b.Bytes()...)
			}
			buf.ReleaseMulti(buffers)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("batch data ownership/order")
		}

		// A full-size GSO packet has a payload smaller than an ABI-sized read
		// buffer. It must not strand the stream in single-buffer mode.
		c.InitializeReadWaiter(N.ReadWaitOptions{IncreaseBuffer: true, BatchSize: 8})
		ipLength := 20
		if v6 {
			ipLength = 40
		}
		nearFull := bytes.Repeat([]byte{0x6a}, 65535-ipLength-20)
		p := lwipGSOTestTCP(v6, seq, server, 16, nearFull)
		if !normalizeLWIPGSO(p.packet, p.options) {
			t.Fatal("normalize near-full")
		}
		if err := f.stack.engine.Input(p.packet); err != nil {
			t.Fatal(err)
		}
		seq += uint32(len(nearFull))
		buffers, err := c.WaitReadBuffers()
		if err != nil || len(buffers) != 1 || !bytes.Equal(buffers[0].Bytes(), nearFull) {
			t.Fatal("near-full read", err)
		}
		buf.ReleaseMulti(buffers)
		for i := 0; i < 2; i++ {
			p = lwipGSOTestTCP(v6, seq, server, 16, want[i*60000:(i+1)*60000])
			if !normalizeLWIPGSO(p.packet, p.options) {
				t.Fatal("normalize bulk")
			}
			if err := f.stack.engine.Input(p.packet); err != nil {
				t.Fatal(err)
			}
			seq += 60000
		}
		got = nil
		for len(got) < len(want) {
			buffers, err = c.WaitReadBuffers()
			if err != nil {
				t.Fatal(err)
			}
			if c.batchReader != nil && len(got) == 0 && len(buffers) != 2 {
				t.Fatal("near-full GSO disabled batching")
			}
			for _, b := range buffers {
				got = append(got, b.Bytes()...)
			}
			buf.ReleaseMulti(buffers)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("resumed bulk stream corrupted")
		}

		c.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 7, RearHeadroom: 13, MTU: 40})
		p = lwipGSOTestTCP(v6, seq, server, 25, []byte("after-batch"))
		if !normalizeLWIPGSO(p.packet, p.options) {
			t.Fatal("normalize tail")
		}
		if err := f.stack.engine.Input(p.packet); err != nil {
			t.Fatal(err)
		}
		b, err := c.WaitReadBuffer()
		if err != nil {
			t.Fatal(err)
		}
		if string(b.Bytes()) != "after-batch" || b.Start() != 7 || b.FreeLen() < 13 {
			t.Fatal("single-buffer fallback")
		}
		b.Release()
		if _, err := c.WaitReadBuffers(); !errors.Is(err, io.EOF) {
			t.Fatal("EOF lost", err)
		}
	}
}

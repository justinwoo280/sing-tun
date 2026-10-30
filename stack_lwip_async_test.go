//go:build with_lwip && (cgo || with_purego)

package tun

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

type lwipBlockedHandler struct {
	lwipTestHandler
	started, release, finished chan struct{}
}

func (h *lwipBlockedHandler) JudgeFlow(protocol uint8, source, destination netip.AddrPort, payload []byte) FlowVerdict {
	if destination.Port() == 1000 {
		close(h.started)
		<-h.release
		close(h.finished)
	}
	return h.lwipTestHandler.JudgeFlow(protocol, source, destination, payload)
}

func TestLWIPAsyncJudgementLifecycle(t *testing.T) {
	for _, closeStack := range []bool{false, true} {
		name := "reset"
		if closeStack {
			name = "close"
		}
		t.Run(name, func(t *testing.T) {
			h := &lwipBlockedHandler{started: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
			var once sync.Once
			release := func() { once.Do(func() { close(h.release) }) }
			defer release()
			device := newLWIPTestTun()
			defer device.Close()
			stack, err := NewLWIP(StackOptions{
				Context: context.Background(), Tun: device, Handler: h, Logger: logger.NOP(), UDPTimeout: time.Minute,
				TunOptions: Options{MTU: 1500, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/24")}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			send := func(port uint16) {
				packet := lwipTestPacket(port, []byte("queued"))
				framed := make([]byte, PacketOffset+len(packet))
				copy(framed[PacketOffset:], packet)
				device.input <- framed
			}
			send(1000)
			select {
			case <-h.started:
			case <-time.After(time.Second):
				t.Fatal("judgement did not start")
			}
			// A blocked policy lookup must not hold the TUN reader or prevent an
			// independent destination from reaching the native stack and UDP NAT.
			send(1001)
			if reply := lwipTestReply(t, device, 17); binary.BigEndian.Uint16(reply[20:]) != 1001 {
				t.Fatal("wrong independently accepted destination")
			}
			if closeStack {
				if err = stack.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				stack.ResetNetwork()
			}
			release()
			<-h.finished
			select {
			case packet := <-device.output:
				t.Fatalf("stale judgement emitted a packet after %s: %x", name, packet)
			case <-time.After(50 * time.Millisecond):
			}
			if !closeStack {
				send(1002)
				if reply := lwipTestReply(t, device, 17); binary.BigEndian.Uint16(reply[20:]) != 1002 {
					t.Fatal("fresh flow after reset lost")
				}
			}
		})
	}
}

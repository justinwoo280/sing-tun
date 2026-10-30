//go:build with_lwip && (cgo || with_purego)

package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	lwip "github.com/justinwoo280/sing-lwip"
	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type lwipTestTun struct {
	input, output chan []byte
	done          chan struct{}
	once          sync.Once
}

func newLWIPTestTun() *lwipTestTun {
	return &lwipTestTun{input: make(chan []byte, 64), output: make(chan []byte, 64), done: make(chan struct{})}
}
func (t *lwipTestTun) Name() (string, error)            { return "memory-lwip", nil }
func (t *lwipTestTun) Start() error                     { return nil }
func (t *lwipTestTun) UpdateRouteOptions(Options) error { return nil }
func (t *lwipTestTun) Read(p []byte) (int, error) {
	select {
	case b := <-t.input:
		return copy(p, b), nil
	case <-t.done:
		return 0, net.ErrClosed
	}
}
func (t *lwipTestTun) Write(p []byte) (int, error) {
	select {
	case t.output <- bytes.Clone(p):
		return len(p), nil
	case <-t.done:
		return 0, net.ErrClosed
	}
}
func (t *lwipTestTun) Close() error { t.once.Do(func() { close(t.done) }); return nil }

type lwipTestHandler struct{}

func (*lwipTestHandler) JudgeFlow(_ uint8, _ netip.AddrPort, destination netip.AddrPort, _ []byte) FlowVerdict {
	switch destination.Port() {
	case 53:
		return FlowVerdict{Action: ActionHijackDNS}
	case 9999:
		return FlowVerdict{Action: ActionDrop}
	case 9998:
		return FlowVerdict{Action: ActionReject}
	}
	return FlowVerdict{Action: ActionAccept}
}
func (*lwipTestHandler) NewConnectionEx(_ context.Context, c net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	c.Close()
}
func (*lwipTestHandler) NewDNSPacket(payload []byte, _ M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	_ = writer.WritePacket(buf.As(append([]byte("dns:"), payload...)), destination)
}
func (*lwipTestHandler) NewPacketConnectionEx(_ context.Context, c N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	defer c.Close()
	w := c.(N.PacketReadWaiter)
	w.InitializeReadWaiter(N.ReadWaitOptions{})
	for {
		p, d, e := w.WaitReadPacket()
		if e != nil {
			return
		}
		if e = c.WritePacket(p, d); e != nil {
			return
		}
	}
}
func lwipTestPacket(port uint16, payload []byte) []byte {
	capture := &lwipCapture{}
	writer := dnsResponseWriter{writeback: capture, source: netip.AddrPortFrom(netip.MustParseAddr("198.18.0.20"), port)}
	_ = writer.WritePacket(buf.As(payload), M.ParseSocksaddr("198.18.0.10:40000"))
	return capture.packet
}
func lwipTestFragments(packet []byte) [][]byte {
	var result [][]byte
	for offset := 0; offset < len(packet)-20; {
		n := min(16, len(packet)-20-offset)
		p := make([]byte, 20+n)
		copy(p, packet[:20])
		copy(p[20:], packet[20+offset:20+offset+n])
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
		binary.BigEndian.PutUint16(p[4:], 42)
		flags := uint16(offset / 8)
		if offset+n < len(packet)-20 {
			flags |= 0x2000
		}
		binary.BigEndian.PutUint16(p[6:], flags)
		ip := header.IPv4(p)
		ip.SetChecksum(0)
		ip.SetChecksum(^ip.CalculateChecksum())
		result = append(result, p)
		offset += n
	}
	return result
}
func lwipTestReply(t *testing.T, f *lwipTestTun, protocol byte) []byte {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case p := <-f.output:
			p = p[PacketOffset:]
			if p[0]>>4 == 4 && p[9] == protocol {
				return p
			}
		case <-timer.C:
			t.Fatal("reply timeout")
		}
	}
}
func TestLWIPDatagramPoliciesAndReset(t *testing.T) {
	f := newLWIPTestTun()
	defer f.Close()
	s, e := NewStack("lwip", StackOptions{Context: context.Background(), Tun: f, Handler: &lwipTestHandler{}, Logger: logger.NOP(), UDPTimeout: time.Second,
		TunOptions: Options{MTU: 1500, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/24")}}})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Start(); e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	send := func(p []byte) {
		if PacketOffset > 0 {
			q := make([]byte, PacketOffset+len(p))
			copy(q[PacketOffset:], p)
			p = q
		}
		f.input <- p
	}
	for _, port := range []uint16{1000, 1001} {
		send(lwipTestPacket(port, []byte("echo")))
		p := lwipTestReply(t, f, 17)
		if string(p[28:]) != "echo" || binary.BigEndian.Uint16(p[20:]) != port {
			t.Fatal("UDP destination lost")
		}
	}
	// The endpoint-independent NAT session already exists. Fragmented DNS must
	// still go through policy, rather than reuse its existing packet connection.
	payload := bytes.Repeat([]byte("d"), 24)
	// A new accepted fragmented destination is judged after native reassembly.
	// Its held snapshot must resume exactly once and preserve the payload/tuple.
	for _, p := range lwipTestFragments(lwipTestPacket(1003, payload)) {
		send(p)
	}
	if p := lwipTestReply(t, f, 17); !bytes.Equal(p[28:], payload) || binary.BigEndian.Uint16(p[20:]) != 1003 {
		t.Fatal("fragmented accept did not resume with its original metadata")
	}
	for _, p := range lwipTestFragments(lwipTestPacket(53, payload)) {
		send(p)
	}
	if p := lwipTestReply(t, f, 17); !bytes.Equal(p[28:], append([]byte("dns:"), payload...)) {
		t.Fatal("fragmented DNS bypassed policy")
	}
	for _, p := range lwipTestFragments(lwipTestPacket(9998, payload)) {
		send(p)
	}
	if p := lwipTestReply(t, f, 1); p[20] != 3 || p[21] != 3 {
		t.Fatal("missing ICMP reject")
	}
	s.ResetNetwork()
	send(lwipTestPacket(1002, []byte("reset")))
	if p := lwipTestReply(t, f, 17); string(p[28:]) != "reset" {
		t.Fatal("UDP network reset failed")
	}
	for _, p := range lwipTestFragments(lwipTestPacket(9999, payload)) {
		send(p)
	}
	select {
	case p := <-f.output:
		t.Fatalf("drop rule emitted packet %x", p)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestLWIPNativeGSOPlatformFallback(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		f := newLWIPTestTun()
		w := &lwipWriteback{tun: f}
		want := bytes.Repeat([]byte{0x3e}, 4097)
		p := lwipGSOTestTCP(v6, 101, 200, 25, want)
		if !normalizeLWIPGSO(p.packet, p.options) {
			t.Fatal("invalid test aggregate")
		}
		if err := w.WriteNativePackets([]lwip.Packet{{Data: p.packet, GSOSize: 1400}}); err != nil {
			t.Fatal(err)
		}
		var got []byte
		for len(got) < len(want) {
			var packet []byte
			select {
			case packet = <-f.output:
			case <-time.After(time.Second):
				t.Fatal("platform fallback timeout")
			}
			if PacketOffset > 0 {
				prefix := make([]byte, PacketOffset)
				PacketFillHeader(prefix, header.IPVersion(packet[PacketOffset:]))
				if !bytes.Equal(prefix, packet[:PacketOffset]) {
					t.Fatal("platform IP family prefix lost")
				}
			}
			packet = packet[PacketOffset:]
			parsed, ok := parseForwardPacket(packet)
			if !ok || len(packet) > 1500 {
				t.Fatal("invalid platform fallback packet")
			}
			tcp := header.TCP(parsed.transport)
			pseudo := header.PseudoHeaderChecksum(header.TCPProtocolNumber, parsed.source.Addr().AsSlice(), parsed.destination.Addr().AsSlice(), uint16(len(tcp)))
			if checksum.Checksum(tcp, pseudo) != 0xffff || tcp.SequenceNumber() != uint32(101+len(got)) {
				t.Fatal("platform fallback checksum/sequence changed")
			}
			got = append(got, tcp.Payload()...)
			if (tcp.Flags()&header.TCPFlagFin != 0) != (len(got) == len(want)) {
				t.Fatal("platform fallback FIN changed")
			}
		}
		if !bytes.Equal(got, want) {
			t.Fatal("platform fallback payload changed")
		}
		f.Close()
	}
}

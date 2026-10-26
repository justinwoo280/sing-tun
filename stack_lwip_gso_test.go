//go:build with_lwip && (cgo || with_purego)

package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type lwipGSOTestPacket struct {
	packet  []byte
	options GSOOptions
}

type lwipGSOTestTun struct {
	*lwipTestTun
	packets chan lwipGSOTestPacket
	stack   *LWIP
}

var _ LinuxTUN = (*lwipGSOTestTun)(nil)

func (*lwipGSOTestTun) FlushDNSCache()                                {}
func (t *lwipGSOTestTun) FrontHeadroom() int                          { return 10 }
func (t *lwipGSOTestTun) BatchSize() int                              { return 128 }
func (t *lwipGSOTestTun) TXChecksumOffload() bool                     { return false }
func (t *lwipGSOTestTun) BatchRead([][]byte, int, []int) (int, error) { return 0, net.ErrClosed }
func (t *lwipGSOTestTun) BatchWrite(packets [][]byte, offset int) (int, error) {
	for _, p := range packets {
		if _, err := t.Write(p[offset:]); err != nil {
			return 0, err
		}
	}
	return len(packets), nil
}
func (t *lwipGSOTestTun) readGSO(buffer []byte) ([]byte, GSOOptions, error) {
	select {
	case p := <-t.packets:
		return buffer[:copy(buffer, p.packet)], p.options, nil
	case <-t.done:
		return nil, GSOOptions{}, net.ErrClosed
	}
}

type lwipGSOTestHandler struct {
	lwipTestHandler
	accepted chan net.Conn
	port     Port
}

func (h *lwipGSOTestHandler) JudgeFlow(protocol uint8, source, destination netip.AddrPort, payload []byte) FlowVerdict {
	if h.port != nil {
		return FlowVerdict{Action: ActionFlow, Port: h.port}
	}
	return h.lwipTestHandler.JudgeFlow(protocol, source, destination, payload)
}
func (h *lwipGSOTestHandler) NewConnectionEx(_ context.Context, c net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	h.accepted <- c
}

func startLWIPGSOTest(t *testing.T, handler *lwipGSOTestHandler, loopback bool) *lwipGSOTestTun {
	t.Helper()
	f := &lwipGSOTestTun{lwipTestTun: newLWIPTestTun(), packets: make(chan lwipGSOTestPacket, 64)}
	options := Options{MTU: 1500, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/24")}, Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/64")}}
	if loopback {
		options.Inet4LoopbackAddress = []netip.Addr{netip.MustParseAddr("198.18.0.20")}
	}
	s, err := NewLWIP(StackOptions{Context: context.Background(), Tun: f, Handler: handler, Logger: logger.NOP(), UDPTimeout: time.Second, TunOptions: options})
	if err != nil {
		t.Fatal(err)
	}
	f.stack = s.(*LWIP)
	t.Cleanup(func() { s.Close(); f.Close() })
	if err = s.Start(); err != nil {
		t.Fatal(err)
	}
	return f
}

func lwipGSOTestTCP(v6 bool, seq, ack uint32, flags byte, data []byte) lwipGSOTestPacket {
	ipLength := 20
	gsoType := GSOTCPv4
	if v6 {
		ipLength = 40
		gsoType = GSOTCPv6
	}
	tcpLength := 20
	if flags&2 != 0 {
		tcpLength += 4 // Negotiate window scaling for >64 KiB reordered input.
	}
	p := make([]byte, ipLength+tcpLength+len(data))
	var src, dst []byte
	if v6 {
		p[0] = 0x60
		p[6] = 6
		p[7] = 64
		a, b := netip.MustParseAddr("fd00::10").As16(), netip.MustParseAddr("fd00::20").As16()
		copy(p[8:24], a[:])
		copy(p[24:40], b[:])
		src = p[8:24]
		dst = p[24:40]
		binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
	} else {
		p[0] = 0x45
		p[8] = 64
		p[9] = 6
		copy(p[12:16], []byte{198, 18, 0, 10})
		copy(p[16:20], []byte{198, 18, 0, 20})
		src = p[12:16]
		dst = p[16:20]
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
		binary.BigEndian.PutUint16(p[10:], ^checksum.Checksum(p[:20], 0))
	}
	tcp := p[ipLength:]
	binary.BigEndian.PutUint16(tcp, 40001)
	binary.BigEndian.PutUint16(tcp[2:], 80)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = byte(tcpLength/4) << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	if tcpLength > 20 {
		copy(tcp[20:24], []byte{3, 3, 3, 1})
	}
	copy(tcp[tcpLength:], data)
	pseudo := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src, dst, uint16(len(tcp)))
	if len(data) == 0 {
		binary.BigEndian.PutUint16(tcp[16:], ^checksum.Checksum(tcp, pseudo))
		return lwipGSOTestPacket{packet: p}
	}
	// A kernel offload packet carries a partial transport checksum.
	binary.BigEndian.PutUint16(tcp[16:], pseudo)
	// Exercise normalization when the IP length still describes one wire
	// segment, rather than the complete aggregate delivered by the driver.
	if len(data) > 1400 {
		if v6 {
			binary.BigEndian.PutUint16(p[4:], uint16(tcpLength+1400))
		} else {
			binary.BigEndian.PutUint16(p[2:], uint16(ipLength+tcpLength+1400))
			p[10], p[11] = 0, 0
			binary.BigEndian.PutUint16(p[10:], ^checksum.Checksum(p[:20], 0))
		}
	}
	return lwipGSOTestPacket{packet: p, options: GSOOptions{GSOType: gsoType, CsumStart: uint16(ipLength), CsumOffset: 16, HdrLen: uint16(ipLength + 20), GSOSize: 1400, NeedsCsum: true}}
}

func lwipGSOTestNext(t *testing.T, packets <-chan []byte, protocol uint8) []byte {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case p := <-packets:
			parsed, ok := parseForwardPacket(p)
			if ok && parsed.protocol == protocol {
				return p
			}
		case <-timer.C:
			t.Fatal("GSO test output timeout")
		}
	}
}

func TestLWIPGSOStreamIntegrity(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		name := "IPv4"
		if v6 {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			h := &lwipGSOTestHandler{accepted: make(chan net.Conn, 1)}
			f := startLWIPGSOTest(t, h, false)
			f.packets <- lwipGSOTestTCP(v6, 100, 0, 2, nil)
			syn := lwipGSOTestNext(t, f.output, 6)
			parsed, _ := parseForwardPacket(syn)
			server := binary.BigEndian.Uint32(parsed.transport[4:]) + 1
			f.packets <- lwipGSOTestTCP(v6, 101, server, 16, nil)
			var c net.Conn
			select {
			case c = <-h.accepted:
			case <-time.After(time.Second):
				t.Fatal("accept timeout")
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			ipLength := 20
			if v6 {
				ipLength = 40
			}
			data := bytes.Repeat([]byte{0xa7}, 65535-ipLength-20)
			probe := lwipGSOTestTCP(v6, 101, server, 24, data)
			if !normalizeLWIPGSO(probe.packet, probe.options) || !f.stack.acceptsGSO(probe.packet) {
				t.Fatal("accepted connection lost receive GSO after handshake cache eviction")
			}
			f.stack.ResetNetwork()
			if !f.stack.acceptsGSO(probe.packet) {
				t.Fatal("UDP network reset disabled GSO for a live TCP connection")
			}
			f.packets <- lwipGSOTestTCP(v6, 101, server, 24, data)
			got := make([]byte, len(data))
			if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, data) {
				t.Fatalf("maximum-sized aggregate: %v", err)
			}
			seq := uint32(101 + len(data))
			first, last := bytes.Repeat([]byte{0x35}, 60000), bytes.Repeat([]byte{0xc9}, 60000)
			// Queue the FIN-bearing tail first. The next read reuses the same Go
			// TUN buffer while lwIP must retain and reorder its own copy. Joining
			// the two aggregates also exercises its >64 KiB pbuf-chain splitting.
			f.packets <- lwipGSOTestTCP(v6, seq+uint32(len(first)), server, 25, last)
			f.packets <- lwipGSOTestTCP(v6, seq, server, 16, first)
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, append(first, last...)) {
				t.Fatalf("reordered aggregates/FIN: length=%d err=%v", len(got), err)
			}
			if _, err = c.Write([]byte("after-fin")); err != nil {
				t.Fatal(err)
			}
			if err = c.Close(); err != nil {
				t.Fatal(err)
			}
			if f.stack.acceptsGSO(probe.packet) {
				t.Fatal("closed connection retained receive GSO eligibility")
			}
		})
	}
}

func TestLWIPGSOUDPBoundaries(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		name := "IPv4"
		if v6 {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			f := startLWIPGSOTest(t, &lwipGSOTestHandler{}, false)
			parts := [][]byte{bytes.Repeat([]byte{0x11}, 1200), bytes.Repeat([]byte{0x22}, 1200), bytes.Repeat([]byte{0x33}, 317)}
			for _, port := range []uint16{1000, 53} {
				ipLength := 20
				p := lwipTestPacket(port, bytes.Join(parts, nil))
				if v6 {
					ipLength = 40
					capture := &lwipCapture{}
					writer := dnsResponseWriter{writeback: capture, source: netip.AddrPortFrom(netip.MustParseAddr("fd00::20"), port)}
					if err := writer.WritePacket(buf.As(bytes.Join(parts, nil)), M.ParseSocksaddr("[fd00::10]:40000")); err != nil {
						t.Fatal(err)
					}
					p = capture.packet
				}
				f.packets <- lwipGSOTestPacket{packet: p, options: GSOOptions{GSOType: GSOUDPL4, CsumStart: uint16(ipLength), CsumOffset: 6, HdrLen: uint16(ipLength + 8), GSOSize: 1200, NeedsCsum: true}}
				for _, want := range parts {
					p = lwipGSOTestNext(t, f.output, 17)
					if port == 53 {
						want = append([]byte("dns:"), want...)
					}
					if !bytes.Equal(p[ipLength+8:], want) || binary.BigEndian.Uint16(p[ipLength:]) != port {
						t.Fatalf("UDP boundary/DNS policy: got %d bytes from port %d", len(p)-ipLength-8, binary.BigEndian.Uint16(p[ipLength:]))
					}
				}
			}
		})
	}
}

type lwipGSOTestPort struct{ packets chan []byte }

func (*lwipGSOTestPort) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("fd01::1")
}
func (*lwipGSOTestPort) PortMTU() uint32           { return 1500 }
func (*lwipGSOTestPort) AttachReturn(Return) error { return nil }
func (*lwipGSOTestPort) DetachReturn(Return) error { return nil }
func (p *lwipGSOTestPort) WritePackets(packets [][]byte) error {
	for _, b := range packets {
		p.packets <- bytes.Clone(b)
	}
	return nil
}

func TestLWIPGSOForwardingFallback(t *testing.T) {
	for _, loopback := range []bool{false, true} {
		name := "port"
		if loopback {
			name = "loopback"
		}
		t.Run(name, func(t *testing.T) {
			port := &lwipGSOTestPort{packets: make(chan []byte, 64)}
			f := startLWIPGSOTest(t, &lwipGSOTestHandler{port: port}, loopback)
			out := port.packets
			if loopback {
				out = f.output
			}
			f.packets <- lwipGSOTestTCP(false, 100, 0, 2, nil)
			lwipGSOTestNext(t, out, 6)
			// Include the short-tail-only case: normalization must not cause a
			// second partial-checksum completion on the fallback path.
			for _, test := range []struct {
				size         int
				checksumOnly bool
			}{{4097, false}, {31, false}, {31, true}} {
				size := test.size
				want := bytes.Repeat([]byte{0x7b}, size)
				packet := lwipGSOTestTCP(false, 101, 200, 25, want)
				if test.checksumOnly {
					packet.options.GSOType = GSONone
					packet.options.HdrLen = 0
					packet.options.GSOSize = 0
				}
				f.packets <- packet
				var got []byte
				for len(got) < size {
					p := lwipGSOTestNext(t, out, 6)
					tcp := header.TCP(p[20:])
					pseudo := header.PseudoHeaderChecksum(header.TCPProtocolNumber, p[12:16], p[16:20], uint16(len(p)-20))
					if len(p) > 1500 || checksum.Checksum(p[:20], 0) != 0xffff || checksum.Checksum(p[20:], pseudo) != 0xffff {
						t.Fatal("invalid fallback size/checksum")
					}
					if tcp.SequenceNumber() != uint32(101+len(got)) {
						t.Fatal("fallback sequence changed")
					}
					got = append(got, tcp.Payload()...)
					if (tcp.Flags()&header.TCPFlagFin != 0) != (len(got) == size) {
						t.Fatal("FIN was not on the final segment")
					}
				}
				if !bytes.Equal(got, want) {
					t.Fatal("fallback payload changed")
				}
			}
		})
	}
}

//go:build linux && with_lwip && (cgo || with_purego)

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// Exercise the actual Linux GRO encoder and decode its virtio metadata, without
// opening a TUN or changing the host network. BatchWrite may swap input slices.
type lwipGROTestTun struct {
	Tun
	headroom, batchSize int
	tcp                 *tcpGROTable
	udp                 *udpGROTable
	gro                 groDisablementFlags
	indices             []int
	output              []lwipGSOTestPacket
	calls, maxBatch     int
	fail                error
	discard             bool
}

func newLWIPGROTestTun() *lwipGROTestTun {
	return &lwipGROTestTun{headroom: virtioNetHdrLen, batchSize: idealBatchSize, tcp: newTCPGROTable(), udp: newUDPGROTable()}
}

var _ LinuxTUN = (*lwipGROTestTun)(nil)

func (*lwipGROTestTun) FlushDNSCache()                                {}
func (t *lwipGROTestTun) FrontHeadroom() int                          { return t.headroom }
func (t *lwipGROTestTun) BatchSize() int                              { return t.batchSize }
func (t *lwipGROTestTun) TXChecksumOffload() bool                     { return false }
func (t *lwipGROTestTun) BatchRead([][]byte, int, []int) (int, error) { return 0, net.ErrClosed }
func (t *lwipGROTestTun) BatchWrite(packets [][]byte, offset int) (int, error) {
	t.calls++
	t.maxBatch = max(t.maxBatch, len(packets))
	t.indices = t.indices[:0]
	if t.headroom > 0 {
		defer t.tcp.reset()
		defer t.udp.reset()
		if err := handleGRO(packets, offset, t.tcp, t.udp, t.gro, &t.indices); err != nil {
			return 0, err
		}
	} else {
		for i := range packets {
			t.indices = append(t.indices, i)
		}
	}
	for _, i := range t.indices {
		if t.discard {
			continue
		}
		var options GSOOptions
		if offset > 0 {
			var h virtioNetHdr
			if err := h.decode(packets[i]); err != nil {
				return 0, err
			}
			var err error
			options, err = h.toGSOOptions()
			if err != nil {
				return 0, err
			}
		}
		t.output = append(t.output, lwipGSOTestPacket{bytes.Clone(packets[i][offset:]), options})
	}
	return len(packets), t.fail
}

func lwipGROTestTCP(v6 bool, seq uint32, flags byte, data []byte) []byte {
	p := lwipGSOTestTCP(v6, seq, 12345, flags, data)
	if len(data) > 0 && !normalizeLWIPGSO(p.packet, p.options) {
		panic("invalid test TCP packet")
	}
	return p.packet
}

func lwipGROTestSplit(t *testing.T, packets []lwipGSOTestPacket) [][]byte {
	t.Helper()
	var result [][]byte
	for _, p := range packets {
		count := 1
		if p.options.GSOSize > 0 {
			count += len(p.packet) / int(p.options.GSOSize)
		}
		buffers, sizes := make([][]byte, count), make([]int, count)
		for i := range buffers {
			buffers[i] = make([]byte, 65536)
		}
		n, err := GSOSplit(p.packet, p.options, buffers, sizes, 0)
		if err != nil {
			t.Fatal(err)
		}
		for i := range n {
			packet := buffers[i][:sizes[i]]
			parsed, ok := parseForwardPacket(packet)
			if !ok {
				t.Fatal("invalid resegmented packet")
			}
			iphLen := len(packet) - len(parsed.transport)
			if !checksumValid(packet, uint8(iphLen), parsed.protocol, parsed.ipVersion == 6) ||
				(parsed.ipVersion == 4 && checksum.Checksum(packet[:iphLen], 0) != 0xffff) {
				t.Fatal("invalid resegmented checksum")
			}
			result = append(result, packet)
		}
	}
	return result
}

func TestLWIPWritebackGROStream(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("v6=%v/reverse=%v", v6, reverse), func(t *testing.T) {
				f := newLWIPGROTestTun()
				w := &lwipWriteback{tun: f, headroom: f.headroom}
				for round := range 3 {
					var packets, saved [][]byte
					var want []byte
					for i := range 137 {
						size, flags := 1400, byte(16)
						if i == 136 {
							size, flags = 317, 24 // short PSH tail
						}
						data := bytes.Repeat([]byte{byte(i + round*37)}, size)
						packets = append(packets, lwipGROTestTCP(v6, uint32(100+len(want)), flags, data))
						want = append(want, data...)
					}
					if reverse {
						slices.Reverse(packets)
					}
					for _, p := range packets {
						saved = append(saved, bytes.Clone(p))
					}
					f.output = nil
					if err := w.WriteReturnPackets(packets); err != nil {
						t.Fatal(err)
					}
					if len(f.output) > 10 || f.maxBatch > f.batchSize {
						t.Fatalf("GRO not batching: writes=%d maxBatch=%d", len(f.output), f.maxBatch)
					}
					for i, p := range packets {
						if !bytes.Equal(p, saved[i]) {
							t.Fatal("GRO overwrote borrowed input")
						}
					}
					segments := lwipGROTestSplit(t, f.output)
					ipLen := 20
					if v6 {
						ipLen = 40
					}
					slices.SortFunc(segments, func(a, b []byte) int {
						return int(binary.BigEndian.Uint32(a[ipLen+4:])) - int(binary.BigEndian.Uint32(b[ipLen+4:]))
					})
					var got []byte
					for i, p := range segments {
						tcp := header.TCP(p[ipLen:])
						if tcp.SequenceNumber() != uint32(100+len(got)) || len(tcp.Payload()) > 1400 ||
							(tcp.Flags()&header.TCPFlagPsh != 0) != (i == len(segments)-1) {
							t.Fatalf("resegmented sequence/size/PSH changed: seq=%d want=%d payload=%d flags=%v last=%v", tcp.SequenceNumber(), 100+len(got), len(tcp.Payload()), tcp.Flags(), i == len(segments)-1)
						}
						got = append(got, tcp.Payload()...)
					}
					if !bytes.Equal(got, want) {
						t.Fatal("resegmented stream changed after buffer reuse")
					}
				}
			})
		}
	}
}

func TestLWIPWritebackGROUDP(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		f := newLWIPGROTestTun()
		w := &lwipWriteback{tun: f, headroom: f.headroom}
		var packets [][]byte
		for i, size := range []int{1200, 1200, 317} {
			data := bytes.Repeat([]byte{byte(i + 1)}, size)
			p := lwipTestPacket(1000, data)
			if v6 {
				c := &lwipCapture{}
				d := dnsResponseWriter{writeback: c, source: M.ParseSocksaddr("[fd00::20]:1000").AddrPort()}
				if err := d.WritePacket(buf.As(data), M.ParseSocksaddr("[fd00::10]:40000")); err != nil {
					t.Fatal(err)
				}
				p = c.packet
			}
			packets = append(packets, p)
		}
		if err := w.WriteReturnPackets(packets); err != nil || len(f.output) != 1 || f.output[0].options.GSOType != GSOUDPL4 {
			t.Fatalf("UDP GRO: writes=%d err=%v", len(f.output), err)
		}
		got := lwipGROTestSplit(t, f.output)
		if len(got) != len(packets) {
			t.Fatal("UDP datagram count changed")
		}
		for i, p := range got {
			parsed, _ := parseForwardPacket(p)
			original, _ := parseForwardPacket(packets[i])
			if parsed.source != original.source || parsed.destination != original.destination || !bytes.Equal(parsed.transport, original.transport) {
				t.Fatal("UDP boundary/address/content changed")
			}
		}
	}
}

func TestLWIPWritebackFallbackAndReuse(t *testing.T) {
	for _, mode := range []string{"no-vnet", "disabled", "control", "checksum", "fragment"} {
		t.Run(mode, func(t *testing.T) {
			f := newLWIPGROTestTun()
			w := &lwipWriteback{tun: f, headroom: f.headroom}
			if err := w.WriteReturnPackets([][]byte{lwipGROTestTCP(false, 100, 16, []byte("a")), lwipGROTestTCP(false, 101, 24, []byte("b"))}); err != nil {
				t.Fatal(err)
			}
			f.output = nil
			packets := [][]byte{lwipGROTestTCP(false, 100, 16, []byte("a")), lwipGROTestTCP(false, 101, 24, []byte("b"))}
			switch mode {
			case "no-vnet":
				w.headroom, f.headroom = 0, 0
			case "disabled":
				f.gro = tcpGRODisabled | udpGRODisabled
			case "control":
				packets[1] = lwipGROTestTCP(false, 101, 17, []byte("b")) // FIN must stay separate
			case "checksum":
				packets[1][36] ^= 1
			case "fragment":
				packets[1][6] |= 0x20
			}
			if err := w.WriteReturnPackets(packets); err != nil || len(f.output) != 2 {
				t.Fatalf("fallback: writes=%d err=%v", len(f.output), err)
			}
			for i, p := range f.output {
				if p.options.GSOType != GSONone || p.options.NeedsCsum || !bytes.Equal(p.packet, packets[i]) {
					t.Fatal("fallback reused stale virtio metadata or changed the packet")
				}
			}
		})
	}
}

func TestLWIPWritebackBoundsAndErrors(t *testing.T) {
	f := newLWIPGROTestTun()
	f.batchSize = 17
	w := &lwipWriteback{tun: f, headroom: f.headroom}
	var packets [][]byte
	for i := range 300 {
		p := lwipGROTestTCP(false, 100, 16, []byte{byte(i)})
		binary.BigEndian.PutUint16(p[20:], uint16(1000+i)) // distinct flows, no merge
		packets = append(packets, p)
	}
	if err := w.WriteReturnPackets(packets); err != nil || len(f.output) != len(packets) || f.maxBatch > 17 {
		t.Fatalf("unbounded batch: max=%d err=%v", f.maxBatch, err)
	}
	// An unusual oversized forwarded packet is passed through, but not retained.
	large := make([]byte, lwipWritebackBufferSize+50)
	large[0] = 0x60
	if err := w.WriteReturnPackets([][]byte{large}); err != nil || !bytes.Equal(f.output[len(f.output)-1].packet, large) {
		t.Fatalf("large fallback packet: %v", err)
	}
	for _, b := range w.buffers {
		if cap(b) > lwipWritebackBufferSize {
			t.Fatal("oversized storage retained")
		}
	}
	f.fail = errors.New("injected TUN failure")
	before := f.calls
	if err := w.WriteReturnPackets(packets); err != f.fail || f.calls != before+1 {
		t.Fatal("write error not propagated immediately")
	}
	f.fail, f.output = nil, nil
	if err := w.WriteReturnPackets(packets[:1]); err != nil || !bytes.Equal(f.output[0].packet, packets[0]) {
		t.Fatal("buffer state corrupted after write failure")
	}
}

func TestLWIPWritebackConcurrent(t *testing.T) {
	f := newLWIPGROTestTun()
	w := &lwipWriteback{tun: f, headroom: f.headroom}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 10 {
				if err := w.WriteReturnPackets([][]byte{lwipTestPacket(uint16(1000+i), []byte{byte(i), byte(j)})}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	seen := make(map[string]bool)
	for _, p := range f.output {
		seen[string(p.packet[28:])] = true
	}
	if len(seen) != 80 {
		t.Fatal("concurrent writeback corrupted packets")
	}
}

func BenchmarkLWIPWritebackGRO(b *testing.B) {
	for _, size := range []int{1460, 8191} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			f := newLWIPGROTestTun()
			f.discard = true
			w := &lwipWriteback{tun: f, headroom: f.headroom}
			packets := make([][]byte, 64)
			for i := range packets {
				packets[i] = lwipGROTestTCP(false, uint32(i*size), 16, bytes.Repeat([]byte{byte(i)}, size))
			}
			if err := w.WriteReturnPackets(packets); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(size * len(packets)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := w.WriteReturnPackets(packets); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

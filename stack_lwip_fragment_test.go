//go:build with_lwip && (cgo || with_purego)

package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func lwipTestIPv6Fragments(packet []byte) [][]byte {
	var fragments [][]byte
	for offset := 0; offset < len(packet)-40; offset += 16 {
		n := min(16, len(packet)-40-offset)
		fragment := make([]byte, 48+n)
		copy(fragment, packet[:40])
		fragment[6], fragment[40] = byte(header.IPv6FragmentExtHdrIdentifier), packet[6]
		binary.BigEndian.PutUint16(fragment[4:], uint16(n+8))
		flags := uint16(offset)
		if offset+n < len(packet)-40 {
			flags |= 1
		}
		binary.BigEndian.PutUint16(fragment[42:], flags)
		binary.BigEndian.PutUint32(fragment[44:], 42)
		copy(fragment[48:], packet[40+offset:40+offset+n])
		fragments = append(fragments, fragment)
	}
	return fragments
}

func TestLWIPFragmentPolicyAndForwarding(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, policy := range []string{"accept", "dns", "drop", "reject", "forward"} {
			for _, tailFirst := range []bool{false, true} {
				if policy == "forward" && tailFirst {
					// Routing a fragment to a port requires the first fragment's
					// tuple. Exercise reordered tails after the first fragment.
					continue
				}
				t.Run(fmt.Sprintf("ipv6=%v/%s/tail-first=%v", v6, policy, tailFirst), func(t *testing.T) {
					device := newLWIPTestTun()
					defer device.Close()
					forward := &lwipGSOTestPort{packets: make(chan []byte, 16)}
					handler := &lwipGSOTestHandler{}
					if policy == "forward" {
						handler.port = forward
					}
					stack, err := NewLWIP(StackOptions{
						Context: context.Background(), Tun: device, Handler: handler, Logger: logger.NOP(), UDPTimeout: time.Minute,
						TunOptions: Options{MTU: 1500, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/24")}, Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/64")}},
					})
					if err != nil {
						t.Fatal(err)
					}
					defer stack.Close()
					if err = stack.Start(); err != nil {
						t.Fatal(err)
					}
					port := map[string]uint16{"accept": 1000, "dns": 53, "drop": 9999, "reject": 9998, "forward": 1000}[policy]
					payload := []byte("a complete reassembled datagram, not just its first fragment")
					packet := lwipTestPacket(port, payload)
					fragments := lwipTestFragments(packet)
					if v6 {
						capture := &lwipCapture{}
						writer := &dnsResponseWriter{writeback: capture, source: netip.AddrPortFrom(netip.MustParseAddr("fd00::20"), port)}
						if err = writer.WritePacket(buf.As(payload), M.ParseSocksaddr("[fd00::10]:40000")); err != nil {
							t.Fatal(err)
						}
						packet = capture.packet
						fragments = lwipTestIPv6Fragments(packet)
					}
					send := func(p []byte) {
						frame := make([]byte, PacketOffset+len(p))
						copy(frame[PacketOffset:], p)
						device.input <- frame
					}
					if !tailFirst {
						send(fragments[0])
					}
					for i := len(fragments) - 1; i > 0; i-- {
						send(fragments[i])
					}
					if tailFirst {
						send(fragments[0])
					}
					if policy == "drop" {
						select {
						case <-device.output:
							t.Fatal("fragmented drop emitted a packet")
						case <-time.After(40 * time.Millisecond):
						}
						return
					}
					if policy == "forward" {
						reassembled := make([]byte, len(payload)+8)
						seen := make(map[int]bool)
						for range fragments {
							select {
							case p := <-forward.packets:
								parsed, ok := parseForwardPacket(p)
								if !ok || !parsed.fragment || seen[parsed.fragmentInfo.offset] {
									t.Fatal("invalid or duplicate forwarded fragment")
								}
								seen[parsed.fragmentInfo.offset] = true
								copy(reassembled[parsed.fragmentInfo.offset:], p[len(p)-parsed.fragmentInfo.length:])
							case <-time.After(time.Second):
								t.Fatal("forwarded fragment was lost")
							}
						}
						if !bytes.Equal(reassembled[8:], payload) {
							t.Fatal("forwarded payload changed")
						}
					} else {
						select {
						case p := <-device.output:
							p = p[PacketOffset:]
							parsed, ok := parseForwardPacket(p)
							if !ok {
								t.Fatal("invalid reply")
							}
							if policy == "reject" {
								if (!v6 && (parsed.protocol != 1 || parsed.transport[0] != 3)) || (v6 && (parsed.protocol != 58 || parsed.transport[0] != 1)) {
									t.Fatal("missing reject reply")
								}
							} else {
								want := payload
								if policy == "dns" {
									want = append([]byte("dns:"), payload...)
								}
								if parsed.protocol != 17 || !bytes.Equal(parsed.transport[8:], want) {
									t.Fatal("partial datagram or incorrect DNS/UDP policy")
								}
							}
						case <-time.After(2 * time.Second):
							t.Fatal("no fragment reply")
						}
					}
				})
			}
		}
	}
}

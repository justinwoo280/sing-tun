//go:build with_lwip && (cgo || with_purego)

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"

	"golang.org/x/sys/unix"
)

// Switch from BatchRead to the native lwIP aggregate reader after delivering
// part of a kernel frame. The pending tail must preserve every wire segment,
// even across another switch back to BatchRead.
func TestLWIPReadGSOPendingSegments(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, udp := range []bool{false, true} {
			t.Run(fmt.Sprintf("ipv6=%v/udp=%v", v6, udp), func(t *testing.T) {
				payload := make([]byte, 128*300+37)
				for i := range payload {
					payload[i] = byte(i/128) ^ byte(i)
				}
				packet := lwipGSOTestTCP(v6, 0xfffffff0, 200, tcpFlagACK|tcpFlagPSH|tcpFlagFIN, payload)
				packet.options.GSOSize = 128
				ipLength := int(packet.options.CsumStart)
				if udp {
					p := make([]byte, ipLength+header.UDPMinimumSize+len(payload))
					copy(p, packet.packet[:ipLength])
					if v6 {
						p[6] = ipProtoUDP
						binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
					} else {
						p[9] = ipProtoUDP
						binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
					}
					binary.BigEndian.PutUint16(p[ipLength:], 40000)
					binary.BigEndian.PutUint16(p[ipLength+2:], 1000)
					binary.BigEndian.PutUint16(p[ipLength+4:], uint16(len(p)-ipLength))
					copy(p[ipLength+8:], payload)
					packet.packet = p
					packet.options.HdrLen = uint16(ipLength + 8)
					packet.options.CsumOffset = 6
					packet.options.GSOType = GSOUDPL4
				}
				if !v6 {
					binary.BigEndian.PutUint16(packet.packet[4:], 32000)
				}
				fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				input := os.NewFile(uintptr(fds[0]), "tun-gso-test")
				output := os.NewFile(uintptr(fds[1]), "kernel-gso-test")
				defer input.Close()
				defer output.Close()
				raw, err := input.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				device := &NativeTun{tunFile: input, readRawConn: raw, vnetHdr: true}
				kind := uint8(unix.VIRTIO_NET_HDR_GSO_TCPV4)
				if v6 {
					kind = unix.VIRTIO_NET_HDR_GSO_TCPV6
				}
				if udp {
					kind = unix.VIRTIO_NET_HDR_GSO_UDP_L4
				}
				wire := make([]byte, virtioNetHdrLen+len(packet.packet))
				vh := virtioNetHdr{flags: unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, gsoType: kind, hdrLen: packet.options.HdrLen,
					gsoSize: packet.options.GSOSize, csumStart: packet.options.CsumStart, csumOffset: packet.options.CsumOffset}
				if err = vh.encode(wire); err != nil {
					t.Fatal(err)
				}
				copy(wire[virtioNetHdrLen:], packet.packet)
				if _, err = output.Write(wire); err != nil {
					t.Fatal(err)
				}
				var got []byte
				segment := 0
				check := func(p []byte) {
					t.Helper()
					parsed, ok := parseForwardPacket(p)
					if !ok {
						t.Fatal("invalid output packet")
					}
					n := min(128, len(payload)-len(got))
					if n <= 0 || len(p) != int(packet.options.HdrLen)+n {
						t.Fatalf("segment %d: length %d", segment, len(p))
					}
					if !v6 && (binary.BigEndian.Uint16(p[4:]) != uint16(32000+segment) || checksum.Checksum(p[:ipLength], 0) != 0xffff) {
						t.Fatal("IPv4 ID or checksum changed across pending reads")
					}
					pseudo := header.PseudoHeaderChecksum(header.TCPProtocolNumber, parsed.source.Addr().AsSlice(), parsed.destination.Addr().AsSlice(), uint16(len(p)-ipLength))
					if udp {
						pseudo = header.PseudoHeaderChecksum(header.UDPProtocolNumber, parsed.source.Addr().AsSlice(), parsed.destination.Addr().AsSlice(), uint16(len(p)-ipLength))
						if int(binary.BigEndian.Uint16(p[ipLength+4:])) != n+8 {
							t.Fatal("UDP boundary changed")
						}
					} else {
						tcp := header.TCP(parsed.transport)
						if tcp.SequenceNumber() != uint32(uint64(0xfffffff0)+uint64(len(got))) ||
							(tcp.Flags()&(header.TCPFlagFin|header.TCPFlagPsh) != 0) != (len(got)+n == len(payload)) {
							t.Fatal("TCP sequence or final flags changed")
						}
					}
					if checksum.Checksum(p[ipLength:], pseudo) != 0xffff {
						t.Fatal("invalid transport checksum")
					}
					got = append(got, p[packet.options.HdrLen:]...)
					segment++
				}
				buffers := [][]byte{make([]byte, 2048), make([]byte, 2048)}
				sizes := make([]int, len(buffers))
				readBatch := func() {
					t.Helper()
					n, err := device.BatchRead(buffers, 0, sizes)
					if err != nil || n == 0 {
						t.Fatalf("batch read: %d, %v", n, err)
					}
					for i := range n {
						check(buffers[i][:sizes[i]])
					}
				}
				readBatch()
				if device.pendingSegment != 2 {
					t.Fatal("batch did not retain the partial aggregate")
				}
				if _, _, err = device.readGSO(make([]byte, 10)); !errors.Is(err, io.ErrShortBuffer) || device.pendingSegment != 2 {
					t.Fatal("short buffer consumed pending segments")
				}
				buffer := make([]byte, gsoMaxSize+virtioNetHdrLen)
				for device.pendingPayload != nil {
					p, options, err := device.readGSO(buffer)
					if err != nil || options.GSOType != GSONone || options.NeedsCsum {
						t.Fatalf("pending wire packet: %+v, %v", options, err)
					}
					check(p)
					if segment == 3 {
						readBatch()
					}
				}
				if !bytes.Equal(got, payload) {
					t.Fatalf("pending tail lost or duplicated: %d bytes, want %d", len(got), len(payload))
				}
				// The next native read must come from the device, not stale state.
				if _, err = output.Write(wire); err != nil {
					t.Fatal(err)
				}
				p, options, err := device.readGSO(buffer)
				if err != nil || !bytes.Equal(p, packet.packet) || options.GSOSize != 128 {
					t.Fatalf("fresh aggregate changed: %v", err)
				}
			})
		}
	}
}

func TestLWIPReadGSOPendingOwnership(t *testing.T) {
	packet := lwipGSOTestTCP(false, 100, 200, tcpFlagACK, bytes.Repeat([]byte{42}, 3000))
	device := &NativeTun{pendingPayload: bytes.Clone(packet.packet), pendingOptions: packet.options}
	original := device.pendingPayload
	p, options, err := device.readGSO(make([]byte, gsoMaxSize+virtioNetHdrLen))
	if err != nil || !bytes.Equal(p, packet.packet) || options != packet.options || device.pendingPayload != nil {
		t.Fatalf("pending aggregate: %v", err)
	}
	p[0] ^= 0xff
	if !bytes.Equal(original, packet.packet) {
		t.Fatal("native reader borrowed NativeTun's reusable buffer")
	}
}

//go:build with_lwip

package tun

import (
	"encoding/binary"
	"fmt"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
)

type lwipGSOReader interface {
	LinuxTUN
	readGSO(buffer []byte) ([]byte, GSOOptions, error)
}

// lwIP can receive a TCP segment larger than its netif MTU. Treat a kernel
// aggregate as one segment, keeping its sequence range and final FIN/PSH.
// UDP must still be segmented to preserve datagram boundaries. Unusual TCP
// headers/control flags also use the existing segment path.
func normalizeLWIPGSO(packet []byte, options GSOOptions) bool {
	if len(packet) > 65535 || options.GSOSize == 0 || options.CsumOffset != header.TCPChecksumOffset {
		return false
	}
	ipLength := int(options.CsumStart)
	switch options.GSOType {
	case GSOTCPv4:
		if ipLength != header.IPv4MinimumSize || len(packet) < ipLength+header.TCPMinimumSize ||
			packet[0] != 0x45 || packet[9] != ipProtoTCP || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return false
		}
	case GSOTCPv6:
		if ipLength != header.IPv6MinimumSize || len(packet) < ipLength+header.TCPMinimumSize ||
			packet[0]>>4 != 6 || packet[6] != ipProtoTCP {
			return false
		}
	default:
		return false
	}
	tcp := header.TCP(packet[ipLength:])
	tcpLength := int(tcp.DataOffset())
	if tcpLength < header.TCPMinimumSize || ipLength+tcpLength != int(options.HdrLen) ||
		int(options.HdrLen) >= len(packet) || tcp.Flags()&header.TCPFlagAck == 0 ||
		tcp.Flags() & ^(header.TCPFlagAck|header.TCPFlagPsh|header.TCPFlagFin) != 0 {
		return false
	}
	var pseudo uint16
	if options.GSOType == GSOTCPv4 {
		ip := header.IPv4(packet)
		ip.SetTotalLength(uint16(len(packet)))
		ip.SetChecksum(0)
		ip.SetChecksum(^ip.CalculateChecksum())
		pseudo = header.PseudoHeaderChecksum(header.TCPProtocolNumber, ip.SourceAddressSlice(), ip.DestinationAddressSlice(), uint16(len(tcp)))
	} else {
		ip := header.IPv6(packet)
		ip.SetPayloadLength(uint16(len(packet) - header.IPv6MinimumSize))
		pseudo = header.PseudoHeaderChecksum(header.TCPProtocolNumber, ip.SourceAddressSlice(), ip.DestinationAddressSlice(), uint16(len(tcp)))
	}
	// Complete offload checksums before the normal packet/policy path. Do not
	// rely on the embedding's native checksum-check configuration.
	tcp.SetChecksum(0)
	tcp.SetChecksum(^checksum.Checksum(tcp, pseudo))
	return true
}

// Only flows already accepted for stream handling may keep their aggregates.
// Packet-forwarding, loopback, rejects and new flows retain wire segmentation.
func (s *LWIP) acceptsGSO(packet []byte) bool {
	parsed, ok := parseForwardPacket(packet)
	if !ok || !parsed.hasFlow || parsed.fragment {
		return false
	}
	s.tcpAccess.RLock()
	_, accepted := s.tcpConns[parsed.flowKey()]
	s.tcpAccess.RUnlock()
	return s.ctx.Err() == nil && accepted
}

func (s *LWIP) readGSOLoop(t lwipGSOReader) {
	buffer := make([]byte, 65536+t.FrontHeadroom())
	var segments [][]byte
	var sizes []int
	for s.ctx.Err() == nil {
		packet, options, err := t.readGSO(buffer)
		if err != nil {
			s.readError(err)
			return
		}
		if normalizeLWIPGSO(packet, options) {
			options.NeedsCsum = false
			if s.acceptsGSO(packet) {
				s.process(packet)
				continue
			}
		}
		// Complete checksum-only offload in place. The packet is consumed before
		// the next read, so the original TUN buffer can be used directly.
		if options.GSOType == GSONone {
			var size [1]int
			_, err = GSOSplit(packet, options, [][]byte{packet}, size[:], 0)
			if err == nil {
				s.process(packet)
			}
		} else if options.GSOSize == 0 || int(options.HdrLen) > len(packet) {
			err = fmt.Errorf("invalid GSO size/header: %+v", options)
		} else {
			count := max(1, (len(packet)-int(options.HdrLen)+int(options.GSOSize)-1)/int(options.GSOSize))
			size := int(options.HdrLen) + int(options.GSOSize)
			for len(segments) < count {
				segments = append(segments, nil)
				sizes = append(sizes, 0)
			}
			for i := range count {
				if len(segments[i]) < size {
					segments[i] = make([]byte, size)
				}
			}
			var n int
			n, err = GSOSplit(packet, options, segments[:count], sizes[:count], 0)
			for i := range n {
				s.process(segments[i][:sizes[i]])
			}
		}
		if err != nil {
			s.readError(err)
			return
		}
	}
}

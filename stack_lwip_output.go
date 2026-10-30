//go:build with_lwip

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"

	lwip "github.com/justinwoo280/sing-lwip"
	"github.com/sagernet/sing-tun/gtcpip/header"
)

var errLWIPGSOUnsupported = errors.New("TUN TCP GSO unavailable")

// Only an explicitly capable device enables native aggregates on its netif.
// writeGSO borrows an immutable packet synchronously and must return
// errLWIPGSOUnsupported only when no packet was accepted, allowing safe software
// segmentation of the same bytes.
type lwipGSOWriter interface {
	LinuxTUN
	canWriteTCPGSO() bool
	writeGSO(packet []byte, options GSOOptions) error
}

func lwipOutputGSO(packet lwip.Packet) (GSOOptions, error) {
	p := packet.Data
	if packet.GSOSize == 0 {
		return GSOOptions{}, nil
	}
	ipLen, kind := 20, GSOTCPv4
	if len(p) < 40 || len(p) > 65535 {
		return GSOOptions{}, fmt.Errorf("invalid native TCP GSO length: %d", len(p))
	}
	if p[0]>>4 == 6 {
		ipLen, kind = 40, GSOTCPv6
		if len(p) < 60 || p[6] != ipProtoTCP || int(binary.BigEndian.Uint16(p[4:])) != len(p)-40 {
			return GSOOptions{}, errors.New("invalid native TCPv6 GSO header")
		}
	} else if p[0] != 0x45 || p[9] != ipProtoTCP || binary.BigEndian.Uint16(p[6:])&0x3fff != 0 || int(binary.BigEndian.Uint16(p[2:])) != len(p) {
		return GSOOptions{}, errors.New("invalid native TCPv4 GSO header")
	}
	tcp := header.TCP(p[ipLen:])
	tcpLen := int(tcp.DataOffset())
	if tcpLen < 20 || tcpLen > 60 || ipLen+tcpLen > len(p) {
		return GSOOptions{}, errors.New("invalid native TCP GSO options")
	}
	if len(p)-ipLen-tcpLen <= int(packet.GSOSize) {
		// Native checksums are complete, including ACKs and wire-sized retry
		// segments tagged by lwIP's per-PCB output hook.
		return GSOOptions{}, nil
	}
	if tcp.Flags()&header.TCPFlagAck == 0 || tcp.Flags() & ^(header.TCPFlagAck|header.TCPFlagPsh|header.TCPFlagFin) != 0 {
		return GSOOptions{}, errors.New("invalid native TCP GSO flags")
	}
	return GSOOptions{GSOType: kind, HdrLen: uint16(ipLen + tcpLen), CsumStart: uint16(ipLen), CsumOffset: 16, GSOSize: packet.GSOSize}, nil
}

func (w *lwipWriteback) WriteNativePackets(packets []lwip.Packet) error {
	w.access.Lock()
	defer w.access.Unlock()
	defer clear(w.packets[:])
	n := 0
	flush := func() error {
		if n == 0 {
			return nil
		}
		err := w.writePackets(w.packets[:n])
		n = 0
		return err
	}
	for _, p := range packets {
		options, err := lwipOutputGSO(p)
		if err != nil {
			return err
		}
		if options.GSOType == GSONone {
			w.packets[n] = p.Data
			n++
			if n == len(w.packets) {
				if err := flush(); err != nil {
					return err
				}
			}
			continue
		}
		if err := flush(); err != nil {
			return err
		}
		if t, ok := w.tun.(lwipGSOWriter); ok {
			err = t.writeGSO(p.Data, options)
			if err == nil {
				continue
			}
			if !errors.Is(err, errLWIPGSOUnsupported) {
				return err
			}
		}
		// Capability can disappear or a device can reject GSO after startup.
		// Segment the original, unmodified full-checksum packet. The ordinary
		// writer retains platform framing, MTU-sized TCP and FIN/PSH semantics.
		count := (len(p.Data) - int(options.HdrLen) + int(options.GSOSize) - 1) / int(options.GSOSize)
		segments, sizes := make([][]byte, count), make([]int, count)
		for i := range segments {
			segments[i] = make([]byte, int(options.HdrLen)+int(options.GSOSize))
		}
		count, err = GSOSplit(p.Data, options, segments, sizes, 0)
		if err != nil {
			return err
		}
		for i := range count {
			segments[i] = segments[i][:sizes[i]]
		}
		if err = w.writePackets(segments[:count]); err != nil {
			return err
		}
	}
	return flush()
}

//go:build linux && with_lwip && (cgo || with_purego)

package tun

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"testing"

	lwip "github.com/justinwoo280/sing-lwip"
	"github.com/sagernet/sing-tun/gtcpip/header"
)

func TestLWIPNativeGSOVirtioOutput(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		file, err := os.CreateTemp(t.TempDir(), "virtio-output")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		device := &NativeTun{tunFile: file, vnetHdr: true, tcpGROTable: newTCPGROTable(), udpGROTable: newUDPGROTable()}
		writer := &lwipWriteback{tun: device, headroom: virtioNetHdrLen}
		data := make([]byte, 60001)
		for i := range data {
			data[i] = byte(i % 251)
		}
		p := lwipGROTestTCP(v6, 101, 25, data)
		saved := bytes.Clone(p)
		packets := []lwip.Packet{{Data: lwipGROTestTCP(v6, 100, 16, nil)}, {Data: p, GSOSize: 1400}, {Data: lwipGROTestTCP(v6, 60103, 16, nil), GSOSize: 1400}}
		if !device.canWriteTCPGSO() {
			t.Fatal("capable device disabled")
		}
		if err = writer.WriteNativePackets(packets); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(p, saved) {
			t.Fatal("native borrowed packet modified")
		}
		if _, err = file.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		encoded, err := io.ReadAll(file)
		if err != nil {
			t.Fatal(err)
		}
		var output []lwipGSOTestPacket
		for len(encoded) > 0 {
			var h virtioNetHdr
			if err = h.decode(encoded); err != nil {
				t.Fatal(err)
			}
			options, err := h.toGSOOptions()
			if err != nil {
				t.Fatal(err)
			}
			encoded = encoded[virtioNetHdrLen:]
			size := int(binary.BigEndian.Uint16(encoded[2:]))
			if v6 {
				size = 40 + int(binary.BigEndian.Uint16(encoded[4:]))
			}
			output = append(output, lwipGSOTestPacket{bytes.Clone(encoded[:size]), options})
			encoded = encoded[size:]
		}
		if len(output) != 3 || output[0].options.GSOType != GSONone || output[2].options.GSOType != GSONone || !output[1].options.NeedsCsum || output[1].options.GSOSize != 1400 {
			t.Fatal("native aggregates/control packet metadata lost")
		}
		assertNativeSegments(t, lwipGROTestSplit(t, output[1:2]), v6, data)
		device.gro.disableTCPGRO()
		if device.canWriteTCPGSO() {
			t.Fatal("disabled capability still advertised")
		}
	}
}

type lwipRejectGSOTestTun struct{ *lwipGROTestTun }

func (*lwipRejectGSOTestTun) canWriteTCPGSO() bool { return true }
func (*lwipRejectGSOTestTun) writeGSO(p []byte, options GSOOptions) error {
	// A rejecting device must leave the borrowed full-checksum packet intact.
	return errLWIPGSOUnsupported
}

func assertNativeSegments(t *testing.T, packets [][]byte, v6 bool, want []byte) {
	t.Helper()
	ipLen := 20
	if v6 {
		ipLen = 40
	}
	var got []byte
	for i, p := range packets {
		tcp := header.TCP(p[ipLen:])
		if tcp.SequenceNumber() != uint32(101+len(got)) || len(tcp.Payload()) > 1400 ||
			(tcp.Flags()&header.TCPFlagFin != 0) != (i == len(packets)-1) ||
			(tcp.Flags()&header.TCPFlagPsh != 0) != (i == len(packets)-1) {
			t.Fatal("native GSO segmentation sequence/MSS/FIN/PSH changed")
		}
		got = append(got, tcp.Payload()...)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("native GSO segmentation payload changed")
	}
}

func TestLWIPNativeGSOFallback(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, reject := range []bool{false, true} {
			f := newLWIPGROTestTun()
			f.gro = tcpGRODisabled | udpGRODisabled
			var device Tun = f
			if reject {
				device = &lwipRejectGSOTestTun{f}
			} else {
				f.headroom = 0 // non-offload device
			}
			w := &lwipWriteback{tun: device, headroom: f.headroom}
			data := bytes.Repeat([]byte{0x47}, 60001)
			p := lwipGROTestTCP(v6, 101, 25, data)
			if err := w.WriteNativePackets([]lwip.Packet{{Data: p, GSOSize: 1400}}); err != nil {
				t.Fatal(err)
			}
			if len(f.output) < 2 {
				t.Fatal("fallback did not segment")
			}
			for _, p := range f.output {
				if p.options.GSOType != GSONone {
					t.Fatal("fallback retained offload metadata")
				}
			}
			assertNativeSegments(t, lwipGROTestSplit(t, f.output), v6, data)
		}
	}
}

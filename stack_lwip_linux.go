//go:build with_lwip

package tun

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/sagernet/sing-tun/gtcpip/header"

	"golang.org/x/sys/unix"
)

// readGSO preserves the kernel's TCP aggregates for the lwIP receive path.
// The returned packet borrows buffer; no native code retains its Go storage.
func (t *NativeTun) readGSO(buffer []byte) ([]byte, GSOOptions, error) {
	t.readAccess.Lock()
	defer t.readAccess.Unlock()
	if len(buffer) < gsoMaxSize+virtioNetHdrLen {
		return nil, GSOOptions{}, io.ErrShortBuffer
	}
	var n int
	if t.pendingLength > 0 {
		n = copy(buffer, t.pendingBuffer[:t.pendingLength])
		t.pendingLength = 0
	} else {
		var err error
		n, err = t.tunFile.Read(buffer)
		if err != nil {
			return nil, GSOOptions{}, err
		}
	}
	return parseVirtioRead(buffer[:n])
}

func (t *NativeTun) canWriteTCPGSO() bool {
	t.writeAccess.Lock()
	defer t.writeAccess.Unlock()
	return t.vnetHdr && t.gro.canTCPGRO()
}

func (t *NativeTun) writeGSO(buffer []byte, offset int, options GSOOptions) error {
	t.writeAccess.Lock()
	defer t.writeAccess.Unlock()
	if !t.vnetHdr || !t.gro.canTCPGRO() {
		return errLWIPGSOUnsupported
	}
	if offset < virtioNetHdrLen || offset > len(buffer) || int(options.HdrLen) > len(buffer)-offset {
		return io.ErrShortBuffer
	}
	p := buffer[offset:]
	h := virtioNetHdr{flags: unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, hdrLen: options.HdrLen,
		gsoSize: options.GSOSize, csumStart: options.CsumStart, csumOffset: options.CsumOffset}
	var src, dst []byte
	switch options.GSOType {
	case GSOTCPv4:
		h.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV4
		src, dst = p[12:16], p[16:20]
	case GSOTCPv6:
		h.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV6
		src, dst = p[8:24], p[24:40]
	default:
		return errLWIPGSOUnsupported
	}
	pseudo := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src, dst, uint16(len(p)-int(options.CsumStart)))
	binary.BigEndian.PutUint16(p[int(options.CsumStart)+int(options.CsumOffset):], pseudo)
	if err := h.encode(buffer[offset-virtioNetHdrLen:]); err != nil {
		return err
	}
	n, err := t.tunFile.Write(buffer[offset-virtioNetHdrLen:])
	if n == 0 && (errors.Is(err, unix.EIO) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP)) {
		t.gro.disableTCPGRO()
		return errLWIPGSOUnsupported
	}
	if err == nil && n != len(buffer)-offset+virtioNetHdrLen {
		return io.ErrShortWrite
	}
	return err
}

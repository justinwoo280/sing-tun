//go:build with_lwip

package tun

import (
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"unsafe"

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

func (t *NativeTun) writeGSO(packet []byte, options GSOOptions) error {
	t.writeAccess.Lock()
	defer t.writeAccess.Unlock()
	if !t.vnetHdr || !t.gro.canTCPGRO() {
		return errLWIPGSOUnsupported
	}
	headerLen := int(options.HdrLen)
	checksumAt := int(options.CsumStart) + int(options.CsumOffset)
	if headerLen < 40 || headerLen > 128 || headerLen >= len(packet) || checksumAt+2 > headerLen {
		return io.ErrShortBuffer
	}
	// Copy only the network/transport headers. The payload remains in the
	// caller's native-output batch, including when the device rejects offload.
	size := virtioNetHdrLen + headerLen
	if cap(t.vnetHdrWriteBuf) < size {
		t.vnetHdrWriteBuf = make([]byte, virtioNetHdrLen+128)
	}
	prefix := t.vnetHdrWriteBuf[:size]
	p := prefix[virtioNetHdrLen:]
	copy(p, packet[:headerLen])
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
	pseudo := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src, dst, uint16(len(packet)-int(options.CsumStart)))
	binary.BigEndian.PutUint16(p[checksumAt:], pseudo)
	if err := h.encode(prefix); err != nil {
		return err
	}
	if cap(t.iovecsOutputDefault) < 2 {
		t.iovecsOutputDefault = make([]unix.Iovec, 2)
	}
	iovecs := t.iovecsOutputDefault[:2]
	iovecs[0] = unix.Iovec{Base: &prefix[0]}
	iovecs[0].SetLen(len(prefix))
	iovecs[1] = unix.Iovec{Base: &packet[headerLen]}
	iovecs[1].SetLen(len(packet) - headerLen)
	defer clear(iovecs)
	raw := t.readRawConn
	if raw == nil {
		var err error
		raw, err = t.tunFile.SyscallConn()
		if err != nil {
			return err
		}
	}
	var n int
	var err error
	pollErr := raw.Write(func(fd uintptr) bool {
		for {
			written, _, errno := unix.Syscall(unix.SYS_WRITEV, fd, uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)))
			if errno == unix.EINTR {
				continue
			}
			if errno == unix.EAGAIN {
				return false
			}
			if errno != 0 {
				err = errno
			} else {
				n = int(written)
			}
			return true
		}
	})
	runtime.KeepAlive(packet)
	if pollErr != nil {
		return pollErr
	}
	if n == 0 && (errors.Is(err, unix.EIO) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP)) {
		t.gro.disableTCPGRO()
		return errLWIPGSOUnsupported
	}
	if err == nil && n != len(packet)+virtioNetHdrLen {
		return io.ErrShortWrite
	}
	return err
}

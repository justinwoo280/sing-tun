//go:build with_lwip

package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	lwip "github.com/justinwoo280/sing-lwip"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const WithLWIP = true

var _ Stack = (*LWIP)(nil)

type LWIP struct {
	options        StackOptions
	ctx            context.Context
	cancel         context.CancelFunc
	lifecycle      sync.Mutex
	closed         bool
	engine         *lwip.Stack
	udpNat         *UDPNat
	dispatcher     *ForwardDispatcher
	dispatchStage  *ForwardStage
	dispatchAccess sync.Mutex
	tcpAccess      sync.RWMutex
	tcpConns       map[flowKey]*lwipTCPConn
	writer         *lwipWriteback
}

func NewLWIP(options StackOptions) (Stack, error) {
	if options.Tun == nil || options.Handler == nil {
		return nil, E.New("lwIP requires a TUN and handler")
	}
	if options.TunOptions.MTU < 576 || options.TunOptions.MTU > 65535 {
		return nil, E.New("lwIP MTU must be between 576 and 65535")
	}
	if options.Context == nil {
		options.Context = context.Background()
	}
	if options.UDPTimeout <= 0 {
		options.UDPTimeout = defaultUDPTimeout
	}
	ctx, cancel := context.WithCancel(options.Context)
	s := &LWIP{options: options, ctx: ctx, cancel: cancel, tcpConns: make(map[flowKey]*lwipTCPConn), writer: &lwipWriteback{tun: options.Tun, multi: options.TunOptions.EXP_MultiPendingPackets}}
	if t, ok := options.Tun.(LinuxTUN); ok {
		s.writer.headroom = t.FrontHeadroom()
	}
	return s, nil
}

func (s *LWIP) Start() error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.engine != nil {
		return os.ErrInvalid
	}
	var a4, a6 netip.Addr
	if len(s.options.TunOptions.Inet4Address) > 0 {
		a4 = s.options.TunOptions.Inet4Address[0].Addr()
	}
	if len(s.options.TunOptions.Inet6Address) > 0 {
		a6 = s.options.TunOptions.Inet6Address[0].Addr()
	}
	udpOptions := UDPNatOptions{
		Handler: s.options.Handler, Prepare: s.preparePacketConnection, Timeout: s.options.UDPTimeout,
		Shared: true, Mapping: s.options.UDPMapping, Filtering: s.options.UDPFiltering, MaxSize: s.options.UDPNATMax,
		InterfaceFinder: s.options.InterfaceFinder,
	}
	s.udpNat = NewUDPNat(udpOptions)
	if err := s.udpNat.Start(); err != nil {
		return err
	}
	var tcpGSO bool
	if t, ok := s.options.Tun.(lwipGSOWriter); ok {
		tcpGSO = t.canWriteTCPGSO()
	}
	engine, err := lwip.New(lwip.Options{MTU: s.options.TunOptions.MTU, IPv4: a4, IPv6: a6, Accept: s.accept, TCPGSO: tcpGSO})
	if err != nil {
		s.udpNat.Close()
		return err
	}
	s.engine = engine
	s.dispatcher = NewForwardDispatcher(s.options.Handler, s.writer, s.options.Logger, s.options.TunOptions.MTU, udpOptions, s.options.ICMPTimeout)
	s.dispatchStage = s.dispatcher.NewStage(nil, s.resumeJudged)
	go s.readLoop()
	go s.writeLoop()
	go func() { <-s.ctx.Done(); s.Close() }()
	return nil
}

func (s *LWIP) ResetNetwork() {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closed || s.engine == nil {
		return
	}
	s.udpNat.Purge()
	s.engine.ResetUDP()
	s.dispatchAccess.Lock()
	s.dispatcher.ResetNetwork()
	s.dispatchStage.Flush()
	s.dispatchAccess.Unlock()
}

func (s *LWIP) Close() error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.cancel()
	s.tcpAccess.Lock()
	clear(s.tcpConns)
	s.tcpAccess.Unlock()
	if s.engine == nil {
		return nil
	}
	s.engine.Close()
	s.udpNat.Close()
	s.dispatchAccess.Lock()
	s.dispatcher.Close()
	s.dispatchAccess.Unlock()
	// The inbound owns the TUN. Its subsequent Close unblocks a pending Read.
	return nil
}

func (s *LWIP) accept(c *lwip.Conn) {
	if s.ctx.Err() != nil {
		c.Abort()
		return
	}
	if c.IsUDP() {
		s.udpLoop(c)
		return
	}
	source, destination := M.SocksaddrFromNetIP(c.Source()), M.SocksaddrFromNetIP(c.Destination())
	switch s.options.Handler.JudgeFlow(uint8(header.TCPProtocolNumber), c.Source(), c.Destination(), nil).Action {
	case ActionReject, ActionDrop:
		c.Abort()
		return
	}
	conn := &lwipTCPConn{Conn: c, owner: s, key: flowKey{protocol: uint8(header.TCPProtocolNumber), source: c.Source(), destination: c.Destination()}}
	s.tcpAccess.Lock()
	if s.ctx.Err() != nil {
		s.tcpAccess.Unlock()
		c.Abort()
		return
	}
	s.tcpConns[conn.key] = conn
	s.tcpAccess.Unlock()
	s.options.Handler.NewConnectionEx(s.ctx, conn, source, destination, nil)
}

// Accepted TCP entries leave the upstream forward dispatcher after the handshake.
// Track the native connection lifetime for receive GSO eligibility instead.
type lwipTCPConn struct {
	*lwip.Conn
	owner         *LWIP
	key           flowKey
	readOptions   N.ReadWaitOptions
	batchReader   lwipStreamBatchReader
	readBatchSize int
	readBuffers   [2]*buf.Buffer
	readSlices    [2][]byte
	readSizes     [2]int
}

func (c *lwipTCPConn) forget() {
	c.owner.tcpAccess.Lock()
	if c.owner.tcpConns[c.key] == c {
		delete(c.owner.tcpConns, c.key)
	}
	c.owner.tcpAccess.Unlock()
}

func (c *lwipTCPConn) Close() error {
	c.forget()
	return c.Conn.Close()
}

func (c *lwipTCPConn) Abort() error {
	c.forget()
	return c.Conn.Abort()
}

func (c *lwipTCPConn) HandshakeFailure(error) error {
	return c.Abort()
}

func (s *LWIP) udpLoop(c *lwip.Conn) {
	defer c.Close()
	buffer := make([]byte, 65535)
	for {
		c.SetReadDeadline(time.Now().Add(s.options.UDPTimeout))
		n, source, destination, err := c.ReadPacket(buffer)
		if err != nil {
			return
		}
		payload := buffer[:n]
		// Per-datagram metadata includes the destination of reassembled packets.
		packet := lwipPacket{conn: c, payload: payload, source: source, destination: destination}
		if s.routeDatagram(&packet) {
			continue
		}
		s.udpNat.NewPacket([][]byte{payload}, M.SocksaddrFromNetIP(source), M.SocksaddrFromNetIP(destination), &packet)
	}
}

type lwipPacket struct {
	conn                *lwip.Conn
	payload             []byte
	source, destination netip.AddrPort
}

func (s *LWIP) preparePacketConnection(source, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	p := userData.(*lwipPacket)
	first := *p
	first.payload = slices.Clone(p.payload)
	writer := &lwipUDPWriter{conn: p.conn, timeout: s.options.UDPTimeout, owner: s, first: &first}
	return true, s.ctx, writer, nil
}

func (s *LWIP) routeDatagram(p *lwipPacket) bool {
	// Share the existing per-flow verdict cache. Reassembled datagrams pass
	// through the same DNS/reject/packet-forwarding path as unfragmented input.
	s.dispatchAccess.Lock()
	if s.dispatchStage.resetSeen != s.dispatcher.resetGeneration.Load() {
		s.dispatchStage.Flush()
	}
	// Most datagrams already acquired an accept verdict before native input.
	// Consult it using the reassembled tuple, without rebuilding IP/UDP headers,
	// copying the payload or calculating a checksum just to parse it again.
	handled, cached := s.dispatchStage.dispatchLWIPDatagram(p.source, p.destination)
	if !cached {
		// A reassembled datagram may be the first complete packet for this
		// tuple. The stage owns its snapshot while judging asynchronously.
		// Accepted snapshots return through native input once, then hit the
		// cached verdict on the next native read before reaching UDP NAT.
		handled = s.dispatchStage.Dispatch(p.packet())
	}
	s.dispatchStage.Flush()
	s.dispatchAccess.Unlock()
	return handled
}

// Called under dispatchAccess, like Dispatch. Packet-forwarding/reject paths
// still need a complete packet; DNS and new/expired flows retain the original
// judgement path. The key includes the destination even for endpoint-independent
// NAT, so a cached accepted destination cannot bypass another destination's policy.
func (d *ForwardStage) dispatchLWIPDatagram(source, destination netip.AddrPort) (handled, cached bool) {
	if d == nil || d.dispatcher.closed.Load() || d.resetSeen != d.dispatcher.resetGeneration.Load() {
		return false, false
	}
	d.access.Lock()
	defer d.access.Unlock()
	entry := d.table[flowKey{protocol: uint8(header.UDPProtocolNumber), source: source, destination: destination}]
	now := d.dispatcher.now()
	if entry == nil || entryExpired(entry, now) {
		return false, false
	}
	switch entry.action {
	case ActionAccept, ActionDrop:
		entry.deadline = now + int64(entry.idle)
		return entry.action == ActionDrop, true
	default:
		return false, false
	}
}

type lwipCapture struct{ packet []byte }

func (*lwipCapture) ReturnHeadroom() int { return 0 }
func (w *lwipCapture) WriteReturnPackets(p [][]byte) error {
	if len(p) > 0 {
		w.packet = p[0]
	}
	return nil
}
func (p *lwipPacket) packet() []byte {
	// Reverse the reply-oriented arguments of the shared UDP/IP encoder.
	w := &lwipCapture{}
	encoder := dnsResponseWriter{writeback: w, source: p.destination}
	_ = encoder.WritePacket(buf.As(p.payload), M.SocksaddrFromNetIP(p.source))
	return w.packet
}
func (s *LWIP) rejectUDP(p *lwipPacket) {
	if parsed, ok := parseForwardPacket(p.packet()); ok {
		if reply, ok := buildReject(&parsed, 0); ok {
			_ = s.writer.WriteReturnPackets([][]byte{reply})
		}
	}
}

type lwipUDPWriter struct {
	conn    *lwip.Conn
	timeout time.Duration
	access  sync.Mutex
	owner   *LWIP
	first   *lwipPacket
}

// Allow the upstream UDP copy engine to receive a complete datagram instead
// of its default 16 KiB buffer. udpNatConn exposes this writer via Upstream.
func (*lwipUDPWriter) WriterMTU() int { return 65535 }

func (w *lwipUDPWriter) HandshakeSuccess() error {
	w.access.Lock()
	w.first = nil
	w.access.Unlock()
	return nil
}
func (w *lwipUDPWriter) HandshakeFailure(error) error {
	w.access.Lock()
	p := w.first
	w.first = nil
	w.access.Unlock()
	if p != nil {
		w.owner.rejectUDP(p)
	}
	return nil
}

func (w *lwipUDPWriter) WritePacket(packet *buf.Buffer, destination M.Socksaddr) error {
	defer packet.Release()
	if !destination.IsIP() {
		return E.New("invalid UDP destination: ", destination)
	}
	_ = w.conn.SetReadDeadline(time.Now().Add(w.timeout))
	return w.conn.WritePacket(packet.Bytes(), destination.AddrPort())
}

func (s *LWIP) process(packet []byte) {
	if s.ctx.Err() != nil || len(packet) < header.IPv4MinimumSize {
		return
	}
	parsed, ok := parseForwardPacket(packet)
	if !ok {
		return
	}
	destination := parsed.destination.Addr()
	if destination == BroadcastAddr(s.options.TunOptions.Inet4Address) || !destination.IsGlobalUnicast() {
		return
	}
	if !parsed.fragment && parsed.protocol == uint8(header.TCPProtocolNumber) && parsed.hasFlow {
		if parsed.ipVersion == 4 && slices.Contains(s.options.TunOptions.Inet4LoopbackAddress, destination) {
			ip := header.IPv4(parsed.network)
			rewriteIPv4TCP(ip, header.TCP(parsed.transport), false, destination, 0, false, parsed.source.Addr(), 0, false)
			_ = s.writer.WriteReturnPackets([][]byte{packet})
			return
		}
		if parsed.ipVersion == 6 && slices.Contains(s.options.TunOptions.Inet6LoopbackAddress, destination) {
			ip := header.IPv6(parsed.network)
			rewriteIPv6TCP(ip, header.TCP(parsed.transport), false, destination, 0, false, parsed.source.Addr(), 0, false)
			_ = s.writer.WriteReturnPackets([][]byte{packet})
			return
		}
	}
	s.dispatchAccess.Lock()
	handled := s.dispatchStage.Dispatch(packet)
	s.dispatchStage.Flush()
	s.dispatchAccess.Unlock()
	if !handled {
		s.input(packet)
	}
}

func (s *LWIP) input(packet []byte) {
	if s.ctx.Err() != nil {
		return
	}
	if err := s.engine.Input(packet); err != nil && !errors.Is(err, net.ErrClosed) {
		s.options.Logger.Trace("lwIP input: ", err)
	}
}

func (s *LWIP) resumeJudged() {
	s.dispatchAccess.Lock()
	defer s.dispatchAccess.Unlock()
	if s.ctx.Err() != nil {
		return
	}
	s.dispatchStage.ResumeJudged(func(packet []byte, meta ForwardFrameMeta) {
		meta.completeChecksum(packet)
		s.input(packet)
	})
	s.dispatchStage.Flush()
}

func (s *LWIP) readLoop() {
	if t, ok := s.options.Tun.(lwipGSOReader); ok && t.FrontHeadroom() > 0 {
		s.readGSOLoop(t)
		return
	}
	if t, ok := s.options.Tun.(WinTun); ok {
		for s.ctx.Err() == nil {
			p, release, err := t.ReadPacket()
			if err != nil {
				s.readError(err)
				return
			}
			s.process(p)
			release()
		}
		return
	}
	if t, ok := s.options.Tun.(LinuxTUN); ok && t.BatchSize() > 1 {
		buffers := make([][]byte, t.BatchSize())
		sizes := make([]int, len(buffers))
		offset := t.FrontHeadroom()
		for i := range buffers {
			buffers[i] = make([]byte, int(s.options.TunOptions.MTU)+offset)
		}
		for s.ctx.Err() == nil {
			n, err := t.BatchRead(buffers, offset, sizes)
			for i := 0; i < n; i++ {
				s.process(buffers[i][offset : offset+sizes[i]])
			}
			if err != nil {
				s.readError(err)
				return
			}
		}
		return
	}
	if t, ok := s.options.Tun.(DarwinTUN); ok && s.options.TunOptions.EXP_MultiPendingPackets {
		for s.ctx.Err() == nil {
			packets, err := t.BatchRead(0, 0)
			for _, p := range packets {
				s.process(p.Bytes())
				p.Release()
			}
			if err != nil {
				s.readError(err)
				return
			}
		}
		return
	}
	buffer := make([]byte, 65535+PacketOffset)
	for s.ctx.Err() == nil {
		n, err := s.options.Tun.Read(buffer)
		if n > PacketOffset {
			s.process(buffer[PacketOffset:n])
		}
		if err != nil {
			s.readError(err)
			return
		}
	}
}

func (s *LWIP) readError(err error) {
	if s.ctx.Err() == nil && !E.IsClosed(err) {
		s.options.Logger.Error("lwIP TUN read: ", err)
	}
	s.cancel()
}
func (s *LWIP) writeLoop() {
	buffer := make([]byte, 1<<20)
	var packets []lwip.Packet
	for {
		var err error
		packets, err = s.engine.ReadPacketBatch(buffer, packets)
		if err != nil {
			return
		}
		if err = s.writer.WriteNativePackets(packets); err != nil {
			if s.ctx.Err() == nil {
				s.options.Logger.Error("lwIP TUN write: ", err)
			}
			s.cancel()
			return
		}
	}
}

// Shared by native output, DNS, rejects and the packet forwarder. Arguments
// contain only IP packets; platform-specific headroom is added here.
type lwipWriteback struct {
	tun      Tun
	headroom int
	multi    bool
	access   sync.Mutex
	buffers  [lwipWritebackBatchSize][]byte
	packets  [lwipWritebackBatchSize][]byte
}

const (
	// Bound both retained storage (4 MiB per writer, allocated on demand) and
	// the number of flows passed to the TUN's fixed-size GRO tables.
	lwipWritebackBatchSize  = 64
	lwipWritebackBufferSize = 65536
)

func (*lwipWriteback) ReturnHeadroom() int { return 0 }
func (w *lwipWriteback) WriteReturnPackets(packets [][]byte) error {
	w.access.Lock()
	defer w.access.Unlock()
	return w.writePackets(packets)
}

func (w *lwipWriteback) writePackets(packets [][]byte) error {
	if t, ok := w.tun.(LinuxTUN); ok {
		if w.headroom == 0 {
			_, err := t.BatchWrite(packets, 0)
			return err
		}
		batchSize := max(1, min(t.BatchSize(), len(w.buffers)))
		for len(packets) > 0 {
			n := min(len(packets), batchSize)
			buffers := w.buffers[:n]
			for i, p := range packets[:n] {
				size := w.headroom + len(p)
				if cap(buffers[i]) < size {
					buffers[i] = make([]byte, max(lwipWritebackBufferSize, size))
				}
				buffers[i] = buffers[i][:size]
				copy(buffers[i][w.headroom:], p)
			}
			// GRO can extend and swap these slices. Keep the resulting headers
			// for reuse, without modifying the caller's borrowed packet storage.
			_, err := t.BatchWrite(buffers, w.headroom)
			for i, b := range buffers {
				if cap(b) > lwipWritebackBufferSize {
					buffers[i] = nil // Unusually large packets must not grow the cache.
				}
			}
			if err != nil {
				return err
			}
			packets = packets[n:]
		}
		return nil
	}
	if t, ok := w.tun.(DarwinTUN); ok && w.multi {
		buffers := make([]*buf.Buffer, len(packets))
		for i, p := range packets {
			buffers[i] = buf.As(p)
		}
		return t.BatchWrite(buffers)
	}
	for _, packet := range packets {
		p := packet
		if PacketOffset > 0 {
			p = make([]byte, PacketOffset+len(packet))
			PacketFillHeader(p, PacketIPVersion(packet))
			copy(p[PacketOffset:], packet)
		}
		if _, err := w.tun.Write(p); err != nil {
			return err
		}
	}
	return nil
}

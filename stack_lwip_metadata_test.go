//go:build with_lwip && (cgo || with_purego)

package tun

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

type lwipMetadataHandler struct {
	lwipTestHandler
	calls  int
	action FlowAction
}

func (h *lwipMetadataHandler) JudgeFlow(_ uint8, _, _ netip.AddrPort, _ []byte) FlowVerdict {
	h.calls++
	return FlowVerdict{Action: h.action}
}

func TestLWIPDatagramMetadataPolicyLifetime(t *testing.T) {
	for _, addresses := range [][3]string{
		{"198.18.0.10:40000", "198.18.0.20:1000", "198.18.0.20:1001"},
		{"[fd00::10]:40000", "[fd00::20]:1000", "[fd00::20]:1001"},
	} {
		h := &lwipMetadataHandler{action: ActionAccept}
		d := NewForwardDispatcher(h, &lwipCapture{}, logger.NOP(), 1500, UDPNatOptions{Timeout: time.Minute}, time.Minute)
		ready := make(chan struct{}, 1)
		stage := d.NewStage(nil, func() { ready <- struct{}{} })
		s := &LWIP{dispatcher: d, dispatchStage: stage}
		p := lwipPacket{source: netip.MustParseAddrPort(addresses[0]), destination: netip.MustParseAddrPort(addresses[1]), payload: []byte("first")}
		judge := func() bool {
			t.Helper()
			if !s.routeDatagram(&p) {
				t.Fatal("new tuple was not held for asynchronous judgement")
			}
			select {
			case <-ready:
			case <-time.After(time.Second):
				t.Fatal("judgement timeout")
			}
			accepted := false
			stage.ResumeJudged(func(packet []byte, _ ForwardFrameMeta) {
				parsed, ok := parseForwardPacket(packet)
				if !ok || parsed.source != p.source || parsed.destination != p.destination {
					t.Fatal("held datagram metadata changed")
				}
				accepted = true
			})
			stage.Flush()
			return !accepted
		}
		if judge() || h.calls != 1 {
			t.Fatal("initial accept judgement lost")
		}
		p.payload = []byte("second")
		if s.routeDatagram(&p) || h.calls != 1 {
			t.Fatal("accepted flow not cached")
		}
		// Endpoint-independent NAT must not apply this verdict to another port.
		p.destination = netip.MustParseAddrPort(addresses[2])
		h.action = ActionDrop
		if !judge() || h.calls != 2 {
			t.Fatal("destination policy bypassed")
		}
		if !s.routeDatagram(&p) || h.calls != 2 {
			t.Fatal("drop verdict not cached")
		}
		for _, entry := range stage.table {
			entry.deadline = -1
		}
		h.action = ActionAccept
		if judge() || h.calls != 3 {
			t.Fatal("expired drop verdict retained")
		}
		d.ResetNetwork()
		if _, cached := stage.dispatchLWIPDatagram(p.source, p.destination); cached {
			t.Fatal("reset pending cache hit")
		}
		h.action = ActionReject
		if !judge() || h.calls != 4 {
			t.Fatal("reset verdict not re-evaluated")
		}
		if _, cached := stage.dispatchLWIPDatagram(p.source, p.destination); cached {
			t.Fatal("reject skipped packet response")
		}
		d.Close()
	}
}

//go:build linux && !android && with_gvisor

package tun

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type backendEchoHandler struct{}

func (backendEchoHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict {
	return FlowVerdict{Action: ActionAccept}
}

func (backendEchoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	_, _ = io.Copy(conn, conn)
}

func (backendEchoHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	_, _ = bufio.CopyPacket(conn, conn)
}

func (backendEchoHandler) NewDNSPacket([]byte, M.Socksaddr, M.Socksaddr, N.PacketWriter) {}

// Check the public factory and common kernel-TUN path for all selectable
// backends, not only the default Go engine's own integration fixtures.
func TestSelectableBackendsKernelEcho(t *testing.T) {
	backends := []string{"", "go", "system", "gvisor", "mixed"}
	if WithLWIP {
		backends = append(backends, "lwip")
	}
	for _, backend := range backends {
		name := backend
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			index := kernelInterfaceSequence.Add(1)
			options := Options{
				Name: fmt.Sprintf("gotest%d", index), MTU: 1500, EXP_ExternalConfiguration: true, Logger: logger.NOP(),
				Inet4Address: []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18 + byte(index>>13), byte(index >> 5), byte(index<<3) | 1}), 29)},
				Inet6Address: []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("fd73:ab91:%x::1/64", index))},
			}
			device, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			defer device.Close()
			configureKernelInterface(t, device, options)
			if err = device.Start(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stack, err := NewStack(backend, StackOptions{
				Context: ctx, Tun: device, TunOptions: options, Handler: backendEchoHandler{}, Logger: logger.NOP(), UDPTimeout: time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			if backend == "" {
				if _, ok := stack.(*Go); !ok {
					t.Fatalf("default backend changed to %T", stack)
				}
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			for _, prefix := range []netip.Prefix{options.Inet4Address[0], options.Inet6Address[0]} {
				destination := netip.AddrPortFrom(prefix.Addr().Next(), 32100)
				for _, network := range []string{"tcp", "udp"} {
					conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, destination.String())
					if err != nil {
						t.Fatalf("%s %s: %v", network, destination, err)
					}
					func() {
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
						payload := bytes.Repeat([]byte("kernel-backend-echo"), 20)
						if _, err = conn.Write(payload); err != nil {
							t.Fatal(err)
						}
						got := make([]byte, len(payload))
						if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
							t.Fatalf("%s %s echo: %v", network, destination, err)
						}
					}()
				}
			}
		})
	}
}

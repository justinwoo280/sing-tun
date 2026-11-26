package tun

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing-tun/internal/winipcfg"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

const (
	kernelConnectionRefused = windows.WSAECONNREFUSED
	kernelConnectionReset   = windows.WSAECONNRESET
)

func kernelSetSocketBuffers(descriptor uintptr, size int) error {
	return E.Errors(
		windows.SetsockoptInt(windows.Handle(descriptor), windows.SOL_SOCKET, windows.SO_RCVBUF, size),
		windows.SetsockoptInt(windows.Handle(descriptor), windows.SOL_SOCKET, windows.SO_SNDBUF, size),
	)
}

var allowKernelInboundUDP = sync.OnceValue(func() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	shortPath, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return err
	}
	longPath := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetLongPathName(shortPath, &longPath[0], uint32(len(longPath)))
	if err != nil {
		return err
	}
	executable = windows.UTF16ToString(longPath[:length])
	const name = "name=sing-tun-test"
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", name).Run()
	output, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", name, "dir=in", "action=allow", "protocol=UDP", "program="+executable, "profile=any").CombinedOutput()
	if err != nil {
		return E.Cause(err, "add firewall rule: ", string(output))
	}
	return nil
})

func configureKernelInterface(t *testing.T, device Tun, options Options) {
	t.Helper()
	err := allowKernelInboundUDP()
	if err != nil {
		t.Fatal(err)
	}
	luid := winipcfg.LUID(device.(*NativeTun).adapter.LUID())
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		addresses := options.Inet4Address
		if family == windows.AF_INET6 {
			addresses = options.Inet6Address
		}
		err := luid.SetIPAddressesForFamily(family, addresses)
		if err != nil {
			t.Fatal(err)
		}
		row, err := luid.IPInterface(family)
		if err != nil {
			t.Fatal(err)
		}
		row.NLMTU = options.MTU
		row.DadTransmits = 0
		row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		err = row.Set()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, addresses := range [][]netip.Prefix{options.Inet4Address, options.Inet6Address} {
		for _, address := range addresses {
			waitKernelInboundUDP(t, device, address.Addr())
		}
	}
}

// Windows quarantines a changed interface until WFP applies its new policy.
// Application allow rules do not override that quarantine. Probe unsolicited
// inbound UDP directly through the TUN before starting the stack or its tests:
// https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/quarantine
func waitKernelInboundUDP(t *testing.T, device Tun, address netip.Addr) {
	t.Helper()
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: address.AsSlice()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// Use a separate socket and peer from the mapping assertions. Never send
	// outbound traffic here: that would allow replies even during quarantine.
	peer := address.Next().Next().Next().Next()
	ipLength := header.IPv4MinimumSize
	if address.Is6() {
		ipLength = header.IPv6MinimumSize
	}
	payload := []byte("kernel-firewall-ready")
	udpLength := uint16(header.UDPMinimumSize + len(payload))
	packet := make([]byte, ipLength+int(udpLength))
	if address.Is4() {
		ip := header.IPv4(packet)
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(packet)), TTL: 64,
			Protocol: uint8(header.UDPProtocolNumber), SrcAddr: peer, DstAddr: address,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
	} else {
		header.IPv6(packet).Encode(&header.IPv6Fields{
			PayloadLength: udpLength, HopLimit: 64,
			TransportProtocol: header.UDPProtocolNumber, SrcAddr: peer, DstAddr: address,
		})
	}
	copy(packet[ipLength+header.UDPMinimumSize:], payload)
	udp := header.UDP(packet[ipLength:])
	storage := make([]byte, len(payload)+1)
	deadline := time.Now().Add(5 * time.Second)
	for port := uint16(40000); time.Now().Before(deadline); port++ {
		udp.Encode(&header.UDPFields{SrcPort: port, DstPort: uint16(client.LocalAddr().(*net.UDPAddr).Port), Length: udpLength})
		pseudo := header.PseudoHeaderChecksum(header.UDPProtocolNumber, peer.AsSlice(), address.AsSlice(), udpLength)
		sum := ^checksum.Checksum(payload, udp.CalculateChecksum(pseudo))
		if sum == 0 {
			sum = 0xffff
		}
		udp.SetChecksum(sum)
		if _, err = device.Write(packet); err != nil {
			t.Fatal(err)
		}
		if err = client.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		n, source, readErr := client.ReadFromUDPAddrPort(storage)
		if readErr == nil {
			if source.Addr() != peer || !bytes.Equal(storage[:n], payload) {
				t.Fatalf("unexpected inbound UDP readiness probe: source=%v payload=%q", source, storage[:n])
			}
			return
		}
		if timeout, ok := readErr.(net.Error); !ok || !timeout.Timeout() {
			t.Fatal(readErr)
		}
	}
	t.Fatalf("Windows interface %v did not become ready for unsolicited inbound UDP", address)
}

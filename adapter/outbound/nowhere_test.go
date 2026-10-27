package outbound

import (
	"net"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
)

// datagramConn mirrors the connected datagram socket the vendored Vector hands
// back: one Read moves exactly one payload and carries no source address.
type datagramConn struct {
	net.Conn
	payload []byte
}

func (c *datagramConn) Read(p []byte) (int, error) {
	return copy(p, c.payload), nil
}

// ReadFrom must never report a nil net.Addr. Mihomo's tunnel demands a
// *net.UDPAddr there: a nil makes handleUDPToLocal fall back to the NAT key and
// log "server return a [<nil>] ... wrongly implemented server" once per
// datagram, which drowns the kernel log of a busy UDP client.
func TestNw3UDPPacketConnReadFromReportsAddr(t *testing.T) {
	tests := []struct {
		name     string
		metadata *C.Metadata
		target   nwtransport.Nw3Target
		want     string
	}{
		{
			name:     "resolved domain reports the dial address",
			metadata: &C.Metadata{NetWork: C.UDP, Host: "example.com", DstIP: netip.MustParseAddr("203.0.113.9"), DstPort: 443},
			target:   mustDomainTarget(t, "example.com", 443),
			want:     "203.0.113.9:443",
		},
		{
			name:     "unresolved domain falls back to the target port",
			metadata: &C.Metadata{NetWork: C.UDP, Host: "example.com", DstPort: 443},
			target:   mustDomainTarget(t, "example.com", 443),
			want:     "0.0.0.0:443",
		},
		{
			name:     "ip target survives missing metadata ip",
			metadata: &C.Metadata{NetWork: C.UDP, DstPort: 53},
			target:   mustIPTarget(t, "192.0.2.7", 53),
			want:     "192.0.2.7:53",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pc := newNw3UDPPacketConn(&datagramConn{payload: []byte("quic")}, test.metadata, test.target)

			n, addr, err := pc.ReadFrom(make([]byte, 64))
			if err != nil {
				t.Fatalf("ReadFrom: %v", err)
			}
			if n != len("quic") {
				t.Fatalf("ReadFrom n = %d, want %d", n, len("quic"))
			}

			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok || udpAddr == nil {
				t.Fatalf("ReadFrom addr = %v (%T), want *net.UDPAddr", addr, addr)
			}
			if got := udpAddr.AddrPort(); got != netip.MustParseAddrPort(test.want) {
				t.Fatalf("ReadFrom addr = %v, want %v", got, test.want)
			}
		})
	}
}

func mustDomainTarget(t *testing.T, host string, port uint16) nwtransport.Nw3Target {
	t.Helper()
	target, err := nwtransport.NewNw3DomainTarget(host, port)
	if err != nil {
		t.Fatalf("domain target %s: %v", host, err)
	}
	return target
}

func mustIPTarget(t *testing.T, addr string, port uint16) nwtransport.Nw3Target {
	t.Helper()
	target, err := nwtransport.NewNw3IPTarget(netip.MustParseAddr(addr), port)
	if err != nil {
		t.Fatalf("ip target %s: %v", addr, err)
	}
	return target
}

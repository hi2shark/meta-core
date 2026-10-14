package nowhere_test

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	nwlisten "github.com/metacubex/mihomo/listener/nowhere"
	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
)

// testNw3Password is a Nowhere 3 service key: exactly 32 lowercase hexadecimal
// characters. The nw2 keys in server_test.go are deliberately not reused here:
// the two stacks have different key rules and must not be mixed.
const testNw3Password = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

func TestResolveNowhereVersion(t *testing.T) {
	for _, testCase := range []struct {
		raw     int
		version int
	}{
		{0, nwtransport.NowhereVersion2},
		{nwtransport.NowhereVersion2, nwtransport.NowhereVersion2},
		{nwtransport.NowhereVersion3, nwtransport.NowhereVersion3},
	} {
		version, err := nwtransport.ResolveNowhereVersion(testCase.raw)
		if err != nil {
			t.Fatalf("ResolveNowhereVersion(%d): %v", testCase.raw, err)
		}
		if version != testCase.version {
			t.Fatalf("ResolveNowhereVersion(%d) = %d, want %d", testCase.raw, version, testCase.version)
		}
	}
	for _, raw := range []int{1, 4, -1} {
		if _, err := nwtransport.ResolveNowhereVersion(raw); err == nil {
			t.Fatalf("ResolveNowhereVersion(%d) = nil error, want a version error", raw)
		}
	}
}

func TestResolveNowhereMorph(t *testing.T) {
	// Nowhere 2 leaves Morph off when omitted, Nowhere 3 turns it on.
	if nwtransport.ResolveNowhereMorph(nil, nwtransport.NowhereVersion2) {
		t.Fatal("omitted morph resolved on for version 2")
	}
	if !nwtransport.ResolveNowhereMorph(nil, nwtransport.NowhereVersion3) {
		t.Fatal("omitted morph resolved off for version 3")
	}
	on, off := true, false
	if !nwtransport.ResolveNowhereMorph(&on, nwtransport.NowhereVersion2) {
		t.Fatal("explicit morph=true ignored for version 2")
	}
	if nwtransport.ResolveNowhereMorph(&off, nwtransport.NowhereVersion3) {
		t.Fatal("explicit morph=false ignored for version 3")
	}
}

func TestNowhereV3Carrier(t *testing.T) {
	for _, testCase := range []struct {
		raw     string
		carrier string
	}{
		{"", nwtransport.NowhereV3CarrierTCP},
		{"tcp", nwtransport.NowhereV3CarrierTCP},
		{"quic", nwtransport.NowhereV3CarrierQUIC},
	} {
		carrier, err := nwtransport.NowhereV3Carrier(testCase.raw)
		if err != nil {
			t.Fatalf("NowhereV3Carrier(%q): %v", testCase.raw, err)
		}
		if carrier != testCase.carrier {
			t.Fatalf("NowhereV3Carrier(%q) = %q, want %q", testCase.raw, carrier, testCase.carrier)
		}
	}
	if _, err := nwtransport.NowhereV3Carrier("ws"); err == nil {
		t.Fatal("NowhereV3Carrier(ws) = nil error, want a carrier error")
	}
}

func TestValidateNowhereV3ServiceKey(t *testing.T) {
	if err := nwtransport.ValidateNowhereV3ServiceKey(testNw3Password); err != nil {
		t.Fatalf("ValidateNowhereV3ServiceKey(%q): %v", testNw3Password, err)
	}
	for _, key := range []string{
		"",
		"xyz",
		// 32–64 is the Nowhere 2 rule; Nowhere 3 wants exactly 32.
		"0123456789abcdef0123456789abcdef01234567",
		"0123456789ABCDEF0123456789ABCDEF",
	} {
		if err := nwtransport.ValidateNowhereV3ServiceKey(key); err == nil {
			t.Fatalf("ValidateNowhereV3ServiceKey(%q) = nil error, want a key error", key)
		}
	}
}

// startNw3TestServer binds 127.0.0.1:0 with the Nowhere 3 Portal on the given
// carrier and reports the port the vendored stack actually listens on.
func startNw3TestServer(t *testing.T, carrier string, morph bool) int {
	t.Helper()
	server, err := nwlisten.NewV3(LC.NowhereServerV3{
		Enable:               true,
		Listen:               "127.0.0.1:0",
		Password:             testNw3Password,
		Certificate:          testCertificate,
		PrivateKey:           testPrivateKey,
		CongestionController: "bbr",
		Carrier:              carrier,
		Morph:                morph,
	}, inbound.NewListenConfig(), fakeTunnel{})
	if err != nil {
		t.Fatalf("nowhere.NewV3: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	addrList := server.AddrList()
	if len(addrList) != 1 {
		t.Fatalf("AddrList = %v, want one address", addrList)
	}
	_, portStr, err := net.SplitHostPort(addrList[0])
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addrList[0], err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}
	return port
}

func newNw3TestClient(t *testing.T, port int, carrier string, morph bool) *outbound.NowhereV3 {
	t.Helper()
	client, err := outbound.NewNowhereV3(outbound.NowhereOption{
		Name: "nowhere-nw3-test-client", Server: "127.0.0.1", Port: port,
		Password: testNw3Password, SkipCertVerify: true,
		Version: nwtransport.NowhereVersion3,
		Carrier: carrier,
		Morph:   &morph,
		UDP:     true,
	})
	if err != nil {
		t.Fatalf("outbound.NewNowhereV3: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// testNw3Forwarding drives one TCP flow and one UDP flow through a Nowhere 3
// endpoint pair and asserts both round-trip through the echo tunnel.
func testNw3Forwarding(t *testing.T, client *outbound.NowhereV3) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := client.DialContext(ctx, &C.Metadata{Host: "example.com", DstPort: 80})
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("nowhere nw3 tcp echo")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("tcp echo = %q, want %q", buf, payload)
	}

	pc, err := client.ListenPacketContext(ctx, &C.Metadata{Host: "example.com", DstPort: 80})
	if err != nil {
		t.Fatalf("ListenPacketContext: %v", err)
	}
	defer func() { _ = pc.Close() }()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))

	udpPayload := []byte("nowhere nw3 udp echo")
	if _, err := pc.WriteTo(udpPayload, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80}); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	udpBuf := make([]byte, len(udpPayload)+1)
	n, _, err := pc.ReadFrom(udpBuf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	if string(udpBuf[:n]) != string(udpPayload) {
		t.Fatalf("udp echo = %q, want %q", udpBuf[:n], udpPayload)
	}
}

// TestNowhereV3TCPForwarding runs a full Nowhere 3 endpoint pair over the TCP
// carrier with Morph on (the Nowhere 3 default): Portal -> echo tunnel and back,
// for a TCP flow and for a UDP flow carried as UoT inside the TLS connection.
func TestNowhereV3TCPForwarding(t *testing.T) {
	port := startNw3TestServer(t, nwtransport.NowhereV3CarrierTCP, true)
	client := newNw3TestClient(t, port, nwtransport.NowhereV3CarrierTCP, true)
	testNw3Forwarding(t, client)
}

// TestNowhereV3TCPForwardingMorphOff is the same pair with Morph explicitly
// disabled on both ends, which is the escape hatch when a middlebox dislikes
// the transform.
func TestNowhereV3TCPForwardingMorphOff(t *testing.T) {
	port := startNw3TestServer(t, nwtransport.NowhereV3CarrierTCP, false)
	client := newNw3TestClient(t, port, nwtransport.NowhereV3CarrierTCP, false)
	testNw3Forwarding(t, client)
}

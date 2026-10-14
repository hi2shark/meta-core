package nowhere_test

import (
	"testing"

	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
)

// TestNowhereV3QUICForwarding runs the same endpoint pair as
// TestNowhereV3TCPForwarding over the QUIC carrier, with Morph on (the Nowhere 3
// default). Unlike the TCP carrier — where the vendored stack wraps Morph itself
// — the host seals the QUIC packet socket below QUIC on both ends, so this test
// exercises nwtransport.ListenNowhereQUIC / DialNowhereQUIC and the
// nw3MorphPacketDialer.
func TestNowhereV3QUICForwarding(t *testing.T) {
	port := startNw3TestServer(t, nwtransport.NowhereNetUDP, true)
	client := newNw3TestClient(t, port, nwtransport.NowhereNetUDP, true)
	testNw3Forwarding(t, client)
}

// TestNowhereV3QUICForwardingMorphOff is the QUIC pair with Morph disabled, the
// escape hatch when the transform breaks a path.
func TestNowhereV3QUICForwardingMorphOff(t *testing.T) {
	port := startNw3TestServer(t, nwtransport.NowhereNetUDP, false)
	client := newNw3TestClient(t, port, nwtransport.NowhereNetUDP, false)
	testNw3Forwarding(t, client)
}

package nowhere

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/transport/nowhere/core/morph"
	"github.com/metacubex/mihomo/transport/nowhere/core/qio"
	"github.com/metacubex/mihomo/transport/nowhere/core/wire"
	"github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

// NowhereV3MaxDatagramSize is the fragment size the vendored core uses when it
// splits a UDP payload across QUIC DATAGRAM frames. The host cannot read
// quic-go's dynamic payload estimate, so the value is pinned below the smallest
// path-MTU-derived bound; 1200 would be rejected by quic-go with
// "DATAGRAM frame too large (maximum: 1163 bytes)".
const NowhereV3MaxDatagramSize = 1000

// NowhereV3ExporterLabel and NowhereV3ExporterLen are the TLS exporter
// parameters the vendored stack binds into every nw3 authentication tag.
const (
	NowhereV3ExporterLabel = wire.ExporterLabel
	NowhereV3ExporterLen   = wire.ExporterLen
)

var errNowhereNilTLS = errors.New("nowhere: missing tls config")

// QIOStream adapts *quic.Stream to the vendored qio.Stream. quic-go's Close
// sends FIN and keeps the receive side open, which is exactly CloseWrite; a
// full Close additionally aborts the receive side, like the reference CLI.
type QIOStream struct {
	*quic.Stream
}

var _ qio.Stream = (*QIOStream)(nil)

func (s *QIOStream) CloseWrite() error { return s.Stream.Close() }

func (s *QIOStream) Close() error {
	s.CancelRead(0)
	return s.Stream.Close()
}

func (s *QIOStream) ID() uint64 { return uint64(s.Stream.StreamID()) }

// QIOConn adapts *quic.Conn to the vendored qio.Conn.
type QIOConn struct {
	conn *quic.Conn
}

var _ qio.Conn = (*QIOConn)(nil)

func NewQIOConn(conn *quic.Conn) *QIOConn {
	return &QIOConn{conn: conn}
}

func (c *QIOConn) TLSVersion() uint16 { return c.conn.ConnectionState().TLS.Version }
func (c *QIOConn) ALPN() string       { return c.conn.ConnectionState().TLS.NegotiatedProtocol }

func (c *QIOConn) Exporter() ([]byte, error) {
	state := c.conn.ConnectionState().TLS
	return (&state).ExportKeyingMaterial(NowhereV3ExporterLabel, []byte{}, NowhereV3ExporterLen)
}

func (c *QIOConn) AcceptStream(ctx context.Context) (qio.Stream, error) {
	stream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &QIOStream{Stream: stream}, nil
}

func (c *QIOConn) OpenStream(ctx context.Context) (qio.Stream, error) {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &QIOStream{Stream: stream}, nil
}

func (c *QIOConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.conn.ReceiveDatagram(ctx)
}

func (c *QIOConn) SendDatagram(b []byte) error { return c.conn.SendDatagram(b) }

func (c *QIOConn) MaxDatagramSize() int { return NowhereV3MaxDatagramSize }

func (c *QIOConn) CloseWithError(code uint64, message string) error {
	return c.conn.CloseWithError(quic.ApplicationErrorCode(code), message)
}

func (c *QIOConn) Context() context.Context { return c.conn.Context() }
func (c *QIOConn) RemoteAddr() net.Addr     { return c.conn.RemoteAddr() }

// QIOListener adapts *quic.Listener to the vendored qio.Listener and applies
// the configured congestion controller to every accepted connection, mirroring
// the nw2 listener's quicListenerAdapter.
type QIOListener struct {
	listener             *quic.Listener
	congestionController string
	cwnd                 int
}

var _ qio.Listener = (*QIOListener)(nil)

func NewQIOListener(listener *quic.Listener, congestionController string, cwnd int) *QIOListener {
	return &QIOListener{listener: listener, congestionController: congestionController, cwnd: cwnd}
}

func (l *QIOListener) Accept(ctx context.Context) (qio.Conn, error) {
	conn, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	common.SetCongestionController(conn, l.congestionController, l.cwnd, "")
	return NewQIOConn(conn), nil
}

func (l *QIOListener) Close() error { return l.listener.Close() }

// DialNowhereQUIC opens the QUIC carrier for the Vector/Egress client. Morph
// seals the packet socket below QUIC on the host side; the TCP carrier is
// wrapped inside the vendored stack, so only QUIC needs this. The TLS config
// already pins TLS 1.3 and ALPN nw3 with session resumption disabled.
func DialNowhereQUIC(ctx context.Context, packetDialer common.PacketDialer, addr string, tlsConfig *tls.Config, quicConfig *quic.Config, keys *morph.Keys, congestionController string, cwnd int) (qio.Conn, error) {
	if tlsConfig == nil {
		return nil, errNowhereNilTLS
	}
	if quicConfig == nil {
		quicConfig = nowhereV3QUICConfig(keys != nil)
	}
	dialer := packetDialer
	if keys != nil {
		dialer = &nw3MorphPacketDialer{inner: packetDialer, keys: *keys}
	}
	_, qconn, err := common.DialQuic(ctx, addr, nil, dialer, tlsConfig, quicConfig, common.DialQuicOption{})
	if err != nil {
		return nil, err
	}
	if congestionController != "" || cwnd != 0 {
		common.SetCongestionController(qconn, congestionController, cwnd, "")
	}
	return NewQIOConn(qconn), nil
}

// ListenNowhereQUIC starts the QUIC listener for the Portal. Morph seals the
// listening socket below QUIC when enabled.
func ListenNowhereQUIC(ctx context.Context, packetConn net.PacketConn, tlsConfig *tls.Config, quicConfig *quic.Config, keys *morph.Keys, congestionController string, cwnd int) (qio.Listener, error) {
	if tlsConfig == nil {
		return nil, errNowhereNilTLS
	}
	if keys != nil {
		packetConn = morph.WrapPacketConn(packetConn, *keys, false)
	}
	if quicConfig == nil {
		quicConfig = nowhereV3QUICConfig(keys != nil)
	}
	// quic.Listen (not ListenEarly): Accept must return connections whose
	// handshake has completed, otherwise the TLS exporter the vendored Portal
	// binds into every auth frame is not yet available.
	listener, err := quic.Listen(packetConn, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	return NewQIOListener(listener, congestionController, cwnd), nil
}

// nowhereV3MaxIncomingStreams bounds the streams the peer may open. quic-go maps
// a negative MaxIncomingStreams to zero, which would forbid the peer from
// opening any stream at all, so the bound must be positive.
const nowhereV3MaxIncomingStreams = (1 << 32) - 1

// nowhereV3QUICConfig is the QUIC carrier's transport config. 0-RTT stays off:
// the vendored stack binds the TLS exporter of a completed handshake into every
// authentication frame, so a resumed handshake would fail to authenticate.
func nowhereV3QUICConfig(morph bool) *quic.Config {
	cfg := &quic.Config{
		EnableDatagrams:                true,
		Allow0RTT:                      false,
		KeepAlivePeriod:                0,
		MaxIdleTimeout:                 120 * time.Second,
		MaxIncomingStreams:             nowhereV3MaxIncomingStreams,
		MaxIncomingUniStreams:          nowhereV3MaxIncomingStreams,
		InitialStreamReceiveWindow:     RecommendedStreamReceiveWindow,
		MaxStreamReceiveWindow:         RecommendedStreamReceiveWindow,
		InitialConnectionReceiveWindow: RecommendedConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     RecommendedConnectionReceiveWindow,
	}
	if morph {
		// Morph seals every datagram with a 12-byte nonce below QUIC. Pin the
		// packet size at the QUIC minimum and skip path-MTU discovery so the
		// UDP payload stays inside a 1212-byte path instead of growing to the
		// link MTU and getting IP-fragmented.
		cfg.DisablePathMTUDiscovery = true
		cfg.InitialPacketSize = 1200
	}
	return cfg
}

// nw3MorphPacketDialer seals every packet socket the QUIC client opens with the
// Nowhere 3 Morph transform.
type nw3MorphPacketDialer struct {
	inner common.PacketDialer
	keys  morph.Keys
}

func (d *nw3MorphPacketDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	pc, err := d.inner.ListenPacket(ctx, network, address, rAddrPort)
	if err != nil {
		return nil, err
	}
	return morph.WrapPacketConn(pc, d.keys, true), nil
}

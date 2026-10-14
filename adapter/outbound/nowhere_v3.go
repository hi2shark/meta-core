package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	stdtls "crypto/tls"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
	"github.com/metacubex/mihomo/transport/nowhere/core/morph"
	"github.com/metacubex/mihomo/transport/nowhere/core/qio"
	"github.com/metacubex/mihomo/transport/nowhere/core/vector"

	"github.com/metacubex/tls"
)

// NowhereV3 is the Nowhere 3 (nw3) proxy outbound. Nowhere 3 speaks exactly one
// carrier per endpoint — tcp (TLS over TCP) or quic — with TLS 1.3, ALPN nw3 and
// no multiplexing: the vendored Vector owns the handshake on both carriers and
// every flow rides its own session. Nowhere 2 keeps its own outbound in
// nowhere.go; the two stacks share no handshake.
type NowhereV3 struct {
	*Base
	option *NowhereOption

	client *vector.Client
}

// DialContext implements C.ProxyAdapter.
func (n *NowhereV3) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	target, err := n.destination(metadata)
	if err != nil {
		return nil, err
	}
	conn, err := n.client.OpenTCP(ctx, target)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, n), nil
}

// ListenPacketContext implements C.ProxyAdapter. Domain targets are passed to
// the Portal unresolved: no local DNS resolution happens here. The vendored
// Vector returns a datagram-oriented net.Conn (one Read/Write moves exactly one
// datagram), which is what NewPacketConn expects.
func (n *NowhereV3) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	target, err := n.destination(metadata)
	if err != nil {
		return nil, err
	}
	pc, err := n.client.OpenUDP(ctx, target)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(N.NewThreadSafePacketConn(&nw3UDPPacketConn{Conn: pc}), n), nil
}

// nw3UDPPacketConn presents the vendored Vector's connected datagram socket
// (one Read/Write moves exactly one payload) as a net.PacketConn, so Mihomo's
// packet machinery can drive it. The flow is bound to a single target, so
// ReadFrom always reports that target and WriteTo ignores the address.
type nw3UDPPacketConn struct {
	net.Conn
	remote net.Addr
}

func (c *nw3UDPPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(p)
	return n, c.remote, err
}

func (c *nw3UDPPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Conn.Write(p)
}

var _ net.PacketConn = (*nw3UDPPacketConn)(nil)

// SupportUOT implements C.ProxyAdapter. The vendored Vector carries a UDP
// association over the same carrier, so UoT is always available.
func (n *NowhereV3) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter.
func (n *NowhereV3) ProxyInfo() C.ProxyInfo {
	info := n.Base.ProxyInfo()
	info.DialerProxy = n.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter.
func (n *NowhereV3) Close() error {
	if n.client != nil {
		return n.client.Close()
	}
	return nil
}

// destination converts Mihomo metadata to the typed Nowhere 3 target. A
// non-IP-literal Host always wins over an already-resolved DstIP so the
// original domain reaches the Portal as a Domain Target; the Portal resolves
// it.
func (n *NowhereV3) destination(metadata *C.Metadata) (nwtransport.Nw3Target, error) {
	if metadata == nil {
		return nwtransport.Nw3Target{}, errors.New("nowhere: nil destination metadata")
	}
	if metadata.Host != "" {
		if address, err := netip.ParseAddr(metadata.Host); err == nil {
			return nwtransport.NewNw3IPTarget(address.Unmap(), metadata.DstPort)
		}
		return nwtransport.NewNw3DomainTarget(metadata.Host, metadata.DstPort)
	}
	if metadata.DstIP.IsValid() {
		return nwtransport.NewNw3IPTarget(metadata.DstIP.Unmap(), metadata.DstPort)
	}
	return nwtransport.Nw3Target{}, errors.New("nowhere: empty destination")
}

// NewNowhereV3 builds the Nowhere 3 outbound. The carrier is resolved first so
// the nw2-only carrier/pool knobs can be rejected before any socket work.
func NewNowhereV3(option NowhereOption) (*NowhereV3, error) {
	if option.Password == "" {
		return nil, fmt.Errorf("nowhere %s: missing password", option.Name)
	}
	if option.Port <= 0 {
		return nil, fmt.Errorf("nowhere %s: invalid port %d", option.Name, option.Port)
	}
	if err := nwtransport.ValidateNowhereV3ServiceKey(option.Password); err != nil {
		return nil, fmt.Errorf("nowhere %s: %w", option.Name, err)
	}
	carrier, err := nwtransport.NowhereV3Carrier(option.Carrier)
	if err != nil {
		return nil, fmt.Errorf("nowhere %s: %w", option.Name, err)
	}
	if err := validateNowhereV3Outbound(option); err != nil {
		return nil, fmt.Errorf("nowhere %s: %w", option.Name, err)
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	serverName := option.Server
	if option.SNI != "" {
		serverName = option.SNI
	}

	base := NewBase(BaseOption{
		Name:         option.Name,
		Addr:         addr,
		Type:         C.Nowhere,
		ProviderName: option.ProviderName,
		UDP:          option.UDP,
		TFO:          option.TFO,
		MPTCP:        option.MPTCP,
		Interface:    option.Interface,
		RoutingMark:  option.RoutingMark,
		Prefer:       option.IPVersion,
	})
	hostDialer := option.NewDialer(base.DialOptions())
	morphEnabled := nwtransport.ResolveNowhereMorph(option.Morph, nwtransport.NowhereVersion3)

	// The QUIC carrier's packet socket is sealed below QUIC on the host side; the
	// TCP carrier is wrapped inside the vendored Vector, so only QUIC needs the
	// keys here.
	var morphKeys *morph.Keys
	if carrier == nwtransport.NowhereV3CarrierQUIC && morphEnabled {
		morphKeys = nwtransport.Nw3MorphKeys(option.Password)
	}
	cfg := vector.Config{
		SharedKey: option.Password,
		Morph:     morphEnabled,
	}
	switch carrier {
	case nwtransport.NowhereV3CarrierTCP:
		cfg.PortalAddr = addr
		cfg.DialTCP = func(ctx context.Context, dialAddr string) (net.Conn, error) {
			return hostDialer.DialContext(ctx, "tcp", dialAddr)
		}
		tlsConfig, err := nw3ClientTLSConfig(option, serverName)
		if err != nil {
			return nil, err
		}
		cfg.TLS = tlsConfig
	default:
		cfg.DialQUIC = func(ctx context.Context) (qio.Conn, error) {
			return nwtransport.DialNowhereV3QUIC(
				ctx,
				nwtransport.NewSourceBoundDialer(nwtransport.DialPolicy{}, hostDialer),
				addr,
				nw3QUICClientTLSConfig(option, serverName),
				nil,
				morphKeys,
				orDefault(option.CongestionController, "bbr"),
				orInt(option.CWND, 32),
			)
		}
	}
	client, err := vector.New(cfg)
	if err != nil {
		return nil, err
	}

	return &NowhereV3{Base: base, option: &option, client: client}, nil
}

// validateNowhereV3Outbound rejects the nw2-only outbound fields: Nowhere 3 uses
// one carrier with fixed pooling, so up/down, mux, pool, the warm-dial knobs and
// the TLS-engine knobs (uTLS fingerprint, ECH) have no Nowhere 3 meaning.
func validateNowhereV3Outbound(option NowhereOption) error {
	if option.Up != "" || option.Down != "" {
		return errors.New("version 3 uses one carrier; remove up and down")
	}
	if option.Mux != nil {
		return errors.New("version 3 has no multiplexing; remove mux")
	}
	if option.Pool != nil {
		return errors.New("version 3 has no connection pool; remove pool")
	}
	if option.PrewarmOnStart {
		return errors.New("version 3 has no prewarming; remove prewarm-on-start")
	}
	if option.MaxConcurrentDials != nil {
		return errors.New("version 3 has no max-concurrent-dials; remove it")
	}
	if option.WarmBackoffInitial != nil || option.WarmBackoffMax != nil {
		return errors.New("version 3 has no warm backoff; remove warm-backoff-initial and warm-backoff-max")
	}
	if len(option.ALPN) > 0 {
		return errors.New("version 3 fixes alpn to nw3; remove alpn")
	}
	if option.Fingerprint != "" {
		return errors.New("version 3 uses the standard TLS stack; remove fingerprint")
	}
	if option.ClientFingerprint != "" {
		return errors.New("version 3 uses the standard TLS stack; remove client-fingerprint")
	}
	if len(option.ECHOpts.Config) > 0 {
		return errors.New("version 3 uses the standard TLS stack; remove ech-opts")
	}
	return nil
}

// nw3ClientTLSConfig is the standard-library client config the vendored Vector
// uses for the TCP carrier. Mihomo's effectiveTLS builds a metacubex/tls config
// (uTLS, ECH), so the nw3 client cannot reuse it: the two types are not
// convertible and Nowhere 3 pins TLS 1.3 with ALPN nw3 anyway.
func nw3ClientTLSConfig(option NowhereOption, serverName string) (*stdtls.Config, error) {
	pin, err := nwtransport.Nw3ParseCertificatePin(option.Pin)
	if err != nil {
		return nil, err
	}
	option.Pin = pin
	tlsConfig := &stdtls.Config{
		ServerName:         serverName,
		MinVersion:         stdtls.VersionTLS13,
		MaxVersion:         stdtls.VersionTLS13,
		NextProtos:         []string{nwtransport.NowhereV3ALPN},
		ClientSessionCache: nil,
		InsecureSkipVerify: option.SkipCertVerify,
	}
	if pin != "" {
		verifier, err := nwtransport.Nw3PeerCertificatePinVerifier(pin)
		if err != nil {
			return nil, err
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = verifier
	}
	return tlsConfig, nil
}

// nw3QUICClientTLSConfig is the metacubex/tls counterpart Mihomo's QUIC stack
// speaks. It mirrors nw3ClientTLSConfig: same pins, same TLS 1.3 / ALPN nw3, no
// session resumption.
func nw3QUICClientTLSConfig(option NowhereOption, serverName string) *tls.Config {
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{nwtransport.NowhereV3ALPN},
		ClientSessionCache: nil,
		InsecureSkipVerify: option.SkipCertVerify,
	}
	if option.Pin != "" {
		if verifier, err := nwtransport.Nw3PeerCertificatePinVerifier(option.Pin); err == nil {
			tlsConfig.InsecureSkipVerify = true
			tlsConfig.VerifyPeerCertificate = verifier
		} else {
			log.Warnln("[Nowhere](%s) invalid pin: %s", option.Name, err)
		}
	}
	return tlsConfig
}

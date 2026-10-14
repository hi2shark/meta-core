// Package nowhere bridges the Nowhere 3 (nw3) Portal and Egress stacks from
// transport/nowhere/core into Mihomo's inbound listener framework. The
// vendored Portal owns its own TLS 1.3 / ALPN nw3 handshake on both carriers,
// so this file only supplies the host QUIC socket, the TLS certificate and the
// tunnel-facing Upstream adapter. Nowhere 2 keeps its own listener in
// server_v2.go; the two stacks never share a handshake.
package nowhere

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
	"github.com/metacubex/mihomo/transport/nowhere/core/egress"
	"github.com/metacubex/mihomo/transport/nowhere/core/portal"
	"github.com/metacubex/mihomo/transport/nowhere/core/qio"
	"github.com/metacubex/mihomo/transport/nowhere/core/wire"

	stdtls "crypto/tls"

	"github.com/metacubex/tls"
)

// nowhereV3EgressReconnectDelay matches the reference CLI: a dropped
// registration waits three seconds before the host dials the Portal again.
const nowhereV3EgressReconnectDelay = 3 * time.Second

// Server is the Nowhere 3 Portal. It serves exactly one carrier with ALPN
// nw3 and TLS 1.3, applies the Nowhere 3 Morph transform when enabled, and
// routes authenticated flows through the tunnel. The TCP carrier rides Mihomo's
// own TCP listener; the QUIC carrier owns a UDP socket on the same address.
// With Egress set the Portal becomes an exit bridge instead: it accepts one
// Egress registration over QUIC and forwards every flow there.
type Server struct {
	config LC.NowhereServer

	ctx    context.Context
	cancel context.CancelFunc

	portal *portal.Server

	tcpListeners []net.Listener
	udpListeners []net.PacketConn
}

// New builds the Nowhere 3 Portal listener.
func New(config LC.NowhereServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*Server, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-NOWHERE"),
			inbound.WithSpecialRules(""),
		}
	}
	if err := nwtransport.ValidateNowhereServiceKey(config.Password); err != nil {
		return nil, fmt.Errorf("nowhere: portal key: %w", err)
	}
	if (config.Certificate == "") != (config.PrivateKey == "") {
		return nil, errors.New("nowhere: certificate and private-key must be set together (omit both for an in-memory self-signed certificate)")
	}
	tlsConfig, quicTLSConfig, err := nw3ServerTLSConfigs(config)
	if err != nil {
		return nil, err
	}
	morphKeys := nwtransport.Nw3MorphKeys(config.Password)
	if !config.Morph {
		morphKeys = nil
	}
	// Egress mode bridges to the registered exit, so the local upstream is
	// unused there; the vendored Portal rejects a nil one otherwise.
	var upstream portal.Upstream
	if !config.Egress {
		upstream = &v3Upstream{tunnel: tunnel, additions: additions}
	}
	portalServer, err := portal.New(portal.Config{
		SharedKey: config.Password,
		Morph:     config.Morph,
		TLS:       tlsConfig,
		Upstream:  upstream,
		Egress:    config.Egress,
	})
	if err != nil {
		return nil, err
	}

	s := &Server{config: config, portal: portalServer}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	success := false
	defer func() {
		if !success {
			_ = s.Close()
		}
	}()

	netName, err := nwtransport.NowhereNet(config.Net)
	if err != nil {
		return nil, err
	}
	for _, addr := range strings.Split(config.Listen, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if netName == nwtransport.NowhereNetTCP {
			tcpListener, err := lc.Listen(context.Background(), "tcp", addr)
			if err != nil {
				return nil, err
			}
			s.tcpListeners = append(s.tcpListeners, tcpListener)
			go func() {
				if err := s.portal.Serve(s.ctx, tcpListener); err != nil && s.ctx.Err() == nil {
					log.Warnln("Nowhere[nw3] TCP serve error: %s", err)
				}
			}()
			continue
		}
		// The QUIC carrier owns its own UDP socket: bind it onto the configured
		// address so the Portal and the Egress client share one port.
		udpConn, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			return nil, err
		}
		quicListener, err := nwtransport.ListenNowhereQUIC(s.ctx, udpConn, quicTLSConfig, nil, morphKeys, config.CongestionController, config.CWND)
		if err != nil {
			_ = udpConn.Close()
			return nil, err
		}
		s.udpListeners = append(s.udpListeners, udpConn)
		go func() {
			if err := s.portal.ServeQUIC(s.ctx, quicListener); err != nil && s.ctx.Err() == nil {
				log.Warnln("Nowhere[nw3] QUIC serve error: %s", err)
			}
		}()
	}

	success = true
	return s, nil
}

// nw3ServerTLSConfigs builds the two server configs the Nowhere 3 Portal needs.
// The vendored Portal performs its own handshakes with the standard library
// (portal.Config.TLS is a *crypto/tls.Config), while Mihomo's QUIC stack speaks
// the metacubex/tls fork. Both are pinned to TLS 1.3 with the single ALPN nw3
// and are derived from the same PEM pair so the two stacks present one identity.
func nw3ServerTLSConfigs(config LC.NowhereServer) (*stdtls.Config, *tls.Config, error) {
	tlsConfig := &stdtls.Config{
		Time:       ntp.Now,
		MinVersion: stdtls.VersionTLS13,
		MaxVersion: stdtls.VersionTLS13,
		NextProtos: []string{nwtransport.NowhereALPN},
	}
	quicTLSConfig := &tls.Config{
		Time:       ntp.Now,
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{nwtransport.NowhereALPN},
	}
	certificate, privateKey := config.Certificate, config.PrivateKey
	if certificate == "" && privateKey == "" {
		var err error
		certificate, privateKey, _, err = ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
		if err != nil {
			return nil, nil, err
		}
	}
	stdLoader, err := newStdTLSKeyPairLoader(certificate, privateKey)
	if err != nil {
		return nil, nil, err
	}
	quicLoader, err := ca.NewTLSKeyPairLoader(certificate, privateKey)
	if err != nil {
		return nil, nil, err
	}
	tlsConfig.GetCertificate = func(*stdtls.ClientHelloInfo) (*stdtls.Certificate, error) {
		return stdLoader()
	}
	quicTLSConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return quicLoader()
	}
	logNowherePortalFingerprint(certificate, privateKey)
	return tlsConfig, quicTLSConfig, nil
}

// logNowherePortalFingerprint prints the leaf certificate SHA-256 so users
// can obtain a pin= value, matching the reference Portal's startup log.
func logNowherePortalFingerprint(certificate, privateKey string) {
	cert, err := stdtls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if err != nil {
		return
	}
	leaf := cert.Leaf
	if leaf == nil {
		return
	}
	log.Infoln("Nowhere[nw3] TLS certificate SHA-256 fingerprint: %s", nwtransport.Nw3LeafCertificateSHA256Hex(leaf.Raw))
}

func (s *Server) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	var retErr error
	for _, listener := range s.udpListeners {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = err
		}
	}
	for _, listener := range s.tcpListeners {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = err
		}
	}
	return retErr
}

func (s *Server) Config() LC.NowhereServer {
	return s.config
}

func (s *Server) AddrList() []string {
	addrList := make([]string, 0, len(s.tcpListeners)+len(s.udpListeners))
	for _, listener := range s.tcpListeners {
		addrList = append(addrList, listener.Addr().String())
	}
	for _, listener := range s.udpListeners {
		addrList = append(addrList, listener.LocalAddr().String())
	}
	return addrList
}

// Egress is the Nowhere 3 Egress client. It never listens: it dials the Portal
// over QUIC, registers as the Portal's single exit, and serves the flows the
// Portal opens through the tunnel. A second Egress is rejected by the Portal
// (egress.ErrBusy) and keeps retrying without preempting the current owner.
type Egress struct {
	config LC.NowhereEgress
	ctx    context.Context

	dialQUIC func(ctx context.Context) (qio.Conn, error)
	upstream *v3Upstream

	runCtx    context.Context
	cancelRun context.CancelFunc
	done      chan struct{}

	closeOnce sync.Once
}

// NewEgress builds the Nowhere 3 Egress inbound.
func NewEgress(ctx context.Context, config LC.NowhereEgress, tunnel C.Tunnel, additions ...inbound.Addition) (*Egress, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-NOWHERE-EGRESS"),
			inbound.WithSpecialRules(""),
		}
	}
	if config.Password == "" {
		return nil, errors.New("nowhere: missing password")
	}
	if err := nwtransport.ValidateNowhereServiceKey(config.Password); err != nil {
		return nil, fmt.Errorf("nowhere: egress key: %w", err)
	}
	if config.Server == "" || config.Port <= 0 || config.Port > 65535 {
		return nil, errors.New("nowhere: missing portal server")
	}
	tlsConfig, err := nw3EgressTLSConfig(config)
	if err != nil {
		return nil, err
	}
	morphKeys := nwtransport.Nw3MorphKeys(config.Password)
	if !config.Morph {
		morphKeys = nil
	}
	addr := net.JoinHostPort(config.Server, strconv.Itoa(config.Port))
	// The Portal connection itself uses the system-selected source address; the
	// exit dials toward targets stay with the tunnel.
	packetDialer := nwtransport.NewSourceBoundDialer(nwtransport.DialPolicy{}, dialer.NewDialer())
	e := &Egress{
		config: config,
		ctx:    ctx,
		upstream: &v3Upstream{
			tunnel:    tunnel,
			additions: additions,
		},
	}
	e.dialQUIC = func(dialCtx context.Context) (qio.Conn, error) {
		return nwtransport.DialNowhereQUIC(dialCtx, packetDialer, addr, tlsConfig, nil, morphKeys, config.CongestionController, config.CWND)
	}
	return e, nil
}

// nw3EgressTLSConfig produces the client config the Egress uses for its Portal
// connection: TLS 1.3, ALPN nw3, and the same trust rules as the Vector.
func nw3EgressTLSConfig(config LC.NowhereEgress) (*tls.Config, error) {
	pin, err := nwtransport.Nw3ParseCertificatePin(config.Pin)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		ServerName:         egressServerName(config),
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{nwtransport.NowhereALPN},
		ClientSessionCache: nil,
		InsecureSkipVerify: config.SkipCertVerify,
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

// egressServerName resolves the verification name: an explicit sni wins,
// otherwise the Portal host is used.
func egressServerName(config LC.NowhereEgress) string {
	if config.SNI != "" {
		return config.SNI
	}
	if net.ParseIP(config.Server) == nil {
		return config.Server
	}
	return ""
}

// Start launches the registration loop. The loop owns one registration at a
// time: egress.Run dials the Portal, registers, and serves flows until the
// connection drops. Every drop returns here, waits out the cooldown, and dials
// again, so a restarted Portal or a stolen exit is picked up without operator
// action.
func (e *Egress) Start() error {
	if e.cancelRun != nil {
		return nil
	}
	e.runCtx, e.cancelRun = context.WithCancel(e.ctx)
	e.done = make(chan struct{})
	go e.run(e.runCtx)
	return nil
}

func (e *Egress) run(ctx context.Context) {
	defer close(e.done)
	for {
		err := egress.Run(ctx, egress.Config{
			SharedKey: e.config.Password,
			DialQUIC:  e.dialQUIC,
			Upstream:  e.upstream,
		})
		if ctx.Err() != nil {
			return
		}
		switch {
		case errors.Is(err, egress.ErrBusy):
			log.Warnln("Nowhere[nw3] egress: portal already has an exit registered; retrying")
		case err != nil:
			log.Warnln("Nowhere[nw3] egress: registration dropped: %s", err)
		default:
			log.Warnln("Nowhere[nw3] egress: registration closed; reconnecting")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(nowhereV3EgressReconnectDelay):
		}
	}
}

func (e *Egress) Close() error {
	e.closeOnce.Do(func() {
		if e.cancelRun != nil {
			e.cancelRun()
		}
		if e.done != nil {
			<-e.done
		}
	})
	return nil
}

func (e *Egress) Config() LC.NowhereEgress {
	return e.config
}

// v3Upstream adapts the Mihomo tunnel to the Nowhere 3 Upstream interface
// shared by the Portal (normal mode) and the Egress client. Both receive a
// target only, so the source address is left unspecified — the same choice the
// sing-box and Xray hosts make.
type v3Upstream struct {
	tunnel    C.Tunnel
	additions []inbound.Addition
}

var _ portal.Upstream = (*v3Upstream)(nil)

// DialTCP hands one authenticated TCP flow to the tunnel. The protocol side of
// a net.Pipe is returned; the router side is tracked by the tunnel and closes
// the pipe when the flow is done.
func (u *v3Upstream) DialTCP(ctx context.Context, target wire.Target) (net.Conn, error) {
	metadata, err := u.buildMetadata(C.TCP, target)
	if err != nil {
		return nil, err
	}
	local, remote := net.Pipe()
	go u.tunnel.HandleTCPConn(remote, metadata)
	return local, nil
}

// DialUDP hands one UDP association to the tunnel. Each Read/Write on the
// returned connection moves exactly one datagram, which is what the vendored
// Portal's UoT and QUIC datagram relays expect.
func (u *v3Upstream) DialUDP(ctx context.Context, target wire.Target) (net.Conn, error) {
	metadata, err := u.buildMetadata(C.UDP, target)
	if err != nil {
		return nil, err
	}
	pc := newV3PacketPipe()
	go u.serveUDP(pc, metadata)
	return pc.netConn(), nil
}

// serveUDP feeds the tunnel one datagram at a time. HandleUDPPacket is
// non-blocking (it queues onto the UDP workers and drops under backpressure),
// so the loop is only bounded by the flow's own lifetime.
func (u *v3Upstream) serveUDP(pc *v3PacketPipe, metadata *C.Metadata) {
	for {
		payload, ok := <-pc.in
		if !ok {
			return
		}
		u.tunnel.HandleUDPPacket(&v3Packet{pc: pc, data: payload, metadata: metadata}, metadata)
	}
}

// buildMetadata maps the wire target to tunnel metadata, the reverse of the
// outbound's destination(): domain targets stay unresolved in Host.
func (u *v3Upstream) buildMetadata(network C.NetWork, target wire.Target) (*C.Metadata, error) {
	metadata := &C.Metadata{
		NetWork: network,
		Type:    C.NOWHERE,
		DstPort: target.Port,
	}
	switch {
	case target.IsIP():
		if !target.Addr.IsValid() {
			return nil, errors.New("nowhere: invalid target address")
		}
		metadata.DstIP = target.Addr
		if network == C.UDP {
			metadata.RawDstAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(target.Addr, target.Port))
		} else {
			metadata.RawDstAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(target.Addr, target.Port))
		}
	case target.Host != "":
		metadata.Host = target.Host
	default:
		return nil, errors.New("nowhere: empty target")
	}
	inbound.ApplyAdditions(metadata, u.additions...)
	return metadata, nil
}

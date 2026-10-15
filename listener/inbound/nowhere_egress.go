package inbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/nowhere"
	"github.com/metacubex/mihomo/log"
	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
)

// NowhereEgressOption is the Nowhere 3 Egress exit: it never listens, it dials a
// Portal over QUIC, registers as that Portal's single exit, and serves the flows
// the Portal opens through the tunnel. A second Egress is rejected by the Portal
// and keeps retrying without preempting the current owner.
type NowhereEgressOption struct {
	BaseOption
	Server string `inbound:"server"`
	// Port is the Portal's port. It cannot reuse the "port" key, which
	// BaseOption already binds to this inbound's own (unused) listen port.
	Port     int    `inbound:"server-port,omitempty"`
	Password string `inbound:"password"`
	// SNI overrides the TLS server name used towards the Portal. Empty uses the
	// Portal host (and disables verification when the host is an IP literal).
	SNI string `inbound:"sni,omitempty"`
	// Pin is the Portal's leaf-certificate SHA-256 (lowercase hex). When set it
	// overrides SNI/chain verification.
	Pin            string `inbound:"pin,omitempty"`
	SkipCertVerify bool   `inbound:"skip-cert-verify,omitempty"`
	// Morph enables the Nowhere 3 keyed transform below QUIC towards the Portal.
	// It defaults to on for Nowhere 3; the Portal must use the same setting.
	Morph                *bool  `inbound:"morph,omitempty"`
	CongestionController string `inbound:"congestion-controller,omitempty"`
	CWND                 int    `inbound:"cwnd,omitempty"`
}

func (o NowhereEgressOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

// NowhereEgress is the Nowhere 3 Egress inbound.
type NowhereEgress struct {
	*Base
	config *NowhereEgressOption
	ts     LC.NowhereEgress
	e      *nowhere.Egress
}

// NewNowhereEgress builds the Nowhere 3 Egress inbound. The shared key must be
// exactly 32 lowercase hexadecimal characters, the Nowhere 3 service-key rule.
func NewNowhereEgress(options *NowhereEgressOption) (*NowhereEgress, error) {
	if options.Password == "" {
		return nil, fmt.Errorf("nowhere-egress %s: missing password", options.Name())
	}
	if err := nwtransport.ValidateNowhereServiceKey(options.Password); err != nil {
		return nil, fmt.Errorf("nowhere-egress %s: %w", options.Name(), err)
	}
	if options.Server == "" {
		return nil, fmt.Errorf("nowhere-egress %s: missing server", options.Name())
	}
	// Rust parses the port as u16.
	if options.Port <= 0 || options.Port > 65535 {
		return nil, fmt.Errorf("nowhere-egress %s: invalid port %d", options.Name(), options.Port)
	}
	// The literal "none" is the Rust sentinel for an omitted sni/pin.
	sni := options.SNI
	if sni == "none" {
		sni = ""
	}
	pin := options.Pin
	if pin == "none" {
		pin = ""
	}
	if pin != "" {
		if _, err := nwtransport.Nw3ParseCertificatePin(pin); err != nil {
			return nil, fmt.Errorf("nowhere-egress %s: %w", options.Name(), err)
		}
	}
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &NowhereEgress{
		Base:   base,
		config: options,
		ts: LC.NowhereEgress{
			Enable:               true,
			Server:               options.Server,
			Port:                 options.Port,
			Password:             options.Password,
			SNI:                  sni,
			Pin:                  pin,
			SkipCertVerify:       options.SkipCertVerify,
			CongestionController: options.CongestionController,
			CWND:                 options.CWND,
			Morph:                nwtransport.ResolveNowhereMorph(options.Morph, true),
		},
	}, nil
}

// Config implements constant.InboundListener
func (n *NowhereEgress) Config() C.InboundConfig {
	return n.config
}

// Address implements constant.InboundListener. The Egress never listens, so it
// reports no address.
func (n *NowhereEgress) Address() string {
	return ""
}

// Listen implements constant.InboundListener. It starts the registration loop;
// the loop owns one registration at a time and reconnects after a drop.
func (n *NowhereEgress) Listen(tunnel C.Tunnel) error {
	e, err := nowhere.NewEgress(context.Background(), n.ts, tunnel, n.Additions()...)
	if err != nil {
		return err
	}
	if err := e.Start(); err != nil {
		_ = e.Close()
		return err
	}
	n.e = e
	log.Infoln("Nowhere[%s] egress registered to: %s", n.Name(), net.JoinHostPort(n.ts.Server, strconv.Itoa(n.ts.Port)))
	return nil
}

// Close implements constant.InboundListener
func (n *NowhereEgress) Close() error {
	if n.e == nil {
		return nil
	}
	return n.e.Close()
}

var _ C.InboundListener = (*NowhereEgress)(nil)

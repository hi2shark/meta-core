package inbound

import (
	"errors"
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/nowhere"
	"github.com/metacubex/mihomo/log"
	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
)

// NewNowhereV3 builds the Nowhere 3 (nw3) inbound. Nowhere 3 serves exactly one
// carrier with ALPN nw3 and TLS 1.3 and owns its own handshake, so the nw2-only
// listener fields (next chaining, ech-key, an explicit alpn) are rejected
// instead of being silently ignored.
func NewNowhereV3(options *NowhereOption) (*NowhereV3, error) {
	if options.Password == "" {
		return nil, fmt.Errorf("nowhere %s: missing password", options.Name())
	}
	if err := nwtransport.ValidateNowhereV3ServiceKey(options.Password); err != nil {
		return nil, fmt.Errorf("nowhere %s: %w", options.Name(), err)
	}
	if (options.Certificate == "") != (options.PrivateKey == "") {
		return nil, fmt.Errorf("nowhere %s: certificate and private-key must be set together (omit both for an in-memory self-signed certificate)", options.Name())
	}
	carrier, err := nwtransport.NowhereV3Carrier(options.Carrier)
	if err != nil {
		return nil, fmt.Errorf("nowhere %s: %w", options.Name(), err)
	}
	if err := validateNowhereV3Inbound(options, carrier); err != nil {
		return nil, fmt.Errorf("nowhere %s: %w", options.Name(), err)
	}
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &NowhereV3{
		Base:   base,
		config: options,
		ts: LC.NowhereServerV3{
			Enable:               true,
			Listen:               base.RawAddress(),
			Password:             options.Password,
			Certificate:          options.Certificate,
			PrivateKey:           options.PrivateKey,
			CongestionController: options.CongestionController,
			CWND:                 options.CWND,
			Carrier:              carrier,
			Egress:               options.Egress,
			Morph:                nwtransport.ResolveNowhereMorph(options.Morph, nwtransport.NowhereVersion3),
		},
	}, nil
}

// validateNowhereV3Inbound rejects the nw2-only listener fields: the vendored
// Portal performs its own handshake, so there is no next-hop chaining, no ECH
// key and no ALPN choice.
func validateNowhereV3Inbound(options *NowhereOption, carrier string) error {
	if options.Next != nil {
		return errors.New("version 3 has no next-hop chaining; remove next")
	}
	if options.EchKey != "" {
		return errors.New("version 3 uses the standard TLS stack; remove ech-key")
	}
	if len(options.ALPN) > 0 {
		return errors.New("version 3 fixes alpn to nw3; remove alpn")
	}
	// The Egress registration handshake only exists on the QUIC carrier.
	if options.Egress && carrier != nwtransport.NowhereV3CarrierQUIC {
		return errors.New("version 3 egress mode requires the quic carrier")
	}
	return nil
}

// NowhereV3 is the Nowhere 3 Portal inbound: authenticated TCP streams and UDP
// packet flows are handed to the tunnel exactly like any other protocol inbound.
type NowhereV3 struct {
	*Base
	config *NowhereOption
	ts     LC.NowhereServerV3
	l      *nowhere.ServerV3
}

// Config implements constant.InboundListener
func (n *NowhereV3) Config() C.InboundConfig {
	return n.config
}

// Equal implements C.InboundConfig, mirroring the Nowhere 2 inbound.
func (n *NowhereV3) Equal(config C.InboundConfig) bool {
	return optionToString(n.config) == optionToString(config)
}

// Address implements constant.InboundListener
func (n *NowhereV3) Address() string {
	var addrList []string
	if n.l != nil {
		addrList = n.l.AddrList()
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (n *NowhereV3) Listen(tunnel C.Tunnel) error {
	var err error
	n.l, err = nowhere.NewV3(n.ts, n.ListenConfig(), tunnel, n.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Nowhere[%s] proxy listening at: %s", n.Name(), n.Address())
	return nil
}

// Close implements constant.InboundListener
func (n *NowhereV3) Close() error {
	if n.l == nil {
		return nil
	}
	return n.l.Close()
}

var _ C.InboundListener = (*NowhereV3)(nil)

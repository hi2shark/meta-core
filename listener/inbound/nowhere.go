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

// NewNowhere builds the Nowhere 3 (nw3) inbound. Nowhere 3 serves exactly one
// transport with ALPN nw3 and TLS 1.3 and owns its own handshake, so the
// Nowhere 2 listener fields (next chaining, ech-key, an alpn other than nw3) are
// rejected instead of being silently ignored.
func NewNowhere(options *NowhereOption) (*Nowhere, error) {
	if options.Password == "" {
		return nil, fmt.Errorf("nowhere %s: missing password", options.Name())
	}
	if err := nwtransport.ValidateNowhereServiceKey(options.Password); err != nil {
		return nil, fmt.Errorf("nowhere %s: %w", options.Name(), err)
	}
	if (options.Certificate == "") != (options.PrivateKey == "") {
		return nil, fmt.Errorf("nowhere %s: certificate and private-key must be set together (omit both for an in-memory self-signed certificate)", options.Name())
	}
	netName, err := nwtransport.NowhereNet(options.Net)
	if err != nil {
		return nil, fmt.Errorf("nowhere %s: %w", options.Name(), err)
	}
	if err := validateNowhereInbound(options, netName); err != nil {
		return nil, fmt.Errorf("nowhere %s: %w", options.Name(), err)
	}
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Nowhere{
		Base:   base,
		config: options,
		ts: LC.NowhereServer{
			Enable:               true,
			Listen:               base.RawAddress(),
			Password:             options.Password,
			Certificate:          options.Certificate,
			PrivateKey:           options.PrivateKey,
			CongestionController: options.CongestionController,
			CWND:                 options.CWND,
			Net:                  netName,
			Egress:               options.Egress,
			Morph:                nwtransport.ResolveNowhereMorph(options.Morph, true),
		},
	}, nil
}

// validateNowhereInbound rejects the Nowhere 2 listener fields: the vendored
// Portal performs its own handshake, so there is no next-hop chaining and no
// ECH key. ALPN is omitted or pinned to nw3.
func validateNowhereInbound(options *NowhereOption, netName string) error {
	nw3, err := nwtransport.SelectNowhereStack(options.ALPN)
	if err != nil {
		return err
	}
	if !nw3 {
		return errors.New("alpn selects the Nowhere 2 stack; omit alpn or set it to nw3")
	}
	if options.Next != nil {
		return errors.New("next is a Nowhere 2 option; set alpn to nw2 or remove it")
	}
	if options.EchKey != "" {
		return errors.New("ech-key is a Nowhere 2 option; set alpn to nw2 or remove it")
	}
	// The Egress registration handshake only exists on QUIC.
	if options.Egress && netName != nwtransport.NowhereNetUDP {
		return errors.New("egress requires net: udp")
	}
	return nil
}

// Nowhere is the Nowhere 3 Portal inbound: authenticated TCP streams and UDP
// packet flows are handed to the tunnel exactly like any other protocol inbound.
type Nowhere struct {
	*Base
	config *NowhereOption
	ts     LC.NowhereServer
	l      *nowhere.Server
}

// Config implements constant.InboundListener
func (n *Nowhere) Config() C.InboundConfig {
	return n.config
}

// Equal implements C.InboundConfig, mirroring the Nowhere 2 inbound.
func (n *Nowhere) Equal(config C.InboundConfig) bool {
	return optionToString(n.config) == optionToString(config)
}

// Address implements constant.InboundListener
func (n *Nowhere) Address() string {
	var addrList []string
	if n.l != nil {
		addrList = n.l.AddrList()
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (n *Nowhere) Listen(tunnel C.Tunnel) error {
	var err error
	n.l, err = nowhere.New(n.ts, n.ListenConfig(), tunnel, n.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Nowhere[%s] proxy listening at: %s", n.Name(), n.Address())
	return nil
}

// Close implements constant.InboundListener
func (n *Nowhere) Close() error {
	if n.l == nil {
		return nil
	}
	return n.l.Close()
}

var _ C.InboundListener = (*Nowhere)(nil)

package inbound

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/nowhere"
	"github.com/metacubex/mihomo/log"
	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
)

type NowhereOption struct {
	BaseOption
	Password             string   `inbound:"password"`
	Certificate          string   `inbound:"certificate,omitempty"`
	PrivateKey           string   `inbound:"private-key,omitempty"`
	EchKey               string   `inbound:"ech-key,omitempty"`
	ALPN                 []string `inbound:"alpn,omitempty"`
	CongestionController string   `inbound:"congestion-controller,omitempty"`
	CWND                 int      `inbound:"cwnd,omitempty"`
	// Morph enables the keyed socket transform below TLS/QUIC. YAML true/1
	// enables it and false/0 disables it. There is no negotiation: the client
	// must use the same setting. An omitted value is off on Nowhere 2 and on
	// on Nowhere 3.
	Morph *bool              `inbound:"morph,omitempty"`
	Next  *NowhereNextOption `inbound:"next,omitempty"`

	// Net is the single Nowhere 3 transport: "tcp" (TLS over TCP, default) or
	// "udp" (QUIC). The Nowhere 2 stack rejects it.
	Net string `inbound:"net,omitempty"`
	// Egress turns the Nowhere 3 Portal into an exit bridge: it accepts a single
	// Egress registration (see the nowhere-egress inbound) and forwards every
	// authenticated flow there instead of to the local tunnel. It requires
	// net: udp, because the registration handshake only exists on QUIC.
	Egress bool `inbound:"egress,omitempty"`
}

// NowhereNextOption is the next-hop Portal for native Portal chaining: when
// set, the listener forwards every inbound flow to another Nowhere 2 Portal
// instead of the tunnel. The next Portal must run Nowhere 2. Validation
// mirrors the outbound's carrier/mux/pool rules (adapter/outbound/nowhere_v2.go).
type NowhereNextOption struct {
	Server   string `inbound:"server"`
	Port     int    `inbound:"port"`
	Password string `inbound:"password"`
	// Up and Down independently select the carrier towards the next Portal
	// ("tcp" or "udp"). Each defaults to "udp" and they must be set together.
	Up   string `inbound:"up,omitempty"`
	Down string `inbound:"down,omitempty"`
	// Mux selects dedicated TLS lanes (0, default) or marked Mux shards (1)
	// towards the next Portal. udp/udp&mux=1 canonicalizes to 0.
	Mux *int `inbound:"mux,omitempty"`
	// Pool is the warm TLS/TCP connection count, only meaningful for dedicated
	// (mux=0) tcp/tcp (default 5 there, 0 otherwise; max tcptls.MaxPoolSize).
	Pool *int `inbound:"pool,omitempty"`
	// Dial4 is the IPv4 source address used towards the next Portal, or
	// "auto". See nwtransport.DialPolicy.
	Dial4 string `inbound:"dial4,omitempty"`
	// Dial6 is the IPv6 source address used towards the next Portal, or
	// "auto". See nwtransport.DialPolicy.
	Dial6 string `inbound:"dial6,omitempty"`
	// SNI overrides the TLS server name used towards the next Portal. Empty or
	// the literal "none" disables certificate verification (a domain server is
	// still sent as ClientHello SNI); an explicit DNS name enables chain+name
	// verification.
	SNI string `inbound:"sni,omitempty"`
	// Pin is the next Portal's leaf-certificate SHA-256 (lowercase hex). When
	// set (non-empty, non-"none") it overrides SNI/chain verification, like
	// the outbound's pin.
	Pin string `inbound:"pin,omitempty"`
	// Morph overrides Morph towards the next Portal. Nil inherits the
	// listener morph flag (official portal:// morph=1 controls both hops).
	Morph *bool `inbound:"morph,omitempty"`
}

func (o NowhereOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type NowhereV2 struct {
	*Base
	config *NowhereOption
	l      *nowhere.ServerV2
	ts     LC.NowhereServerV2
}

// NewNowhereV2 builds the Nowhere 2 inbound. An omitted ALPN, or alpn nw3, is the
// Nowhere 3 default and must be built by NewNowhere.
func NewNowhereV2(options *NowhereOption) (*NowhereV2, error) {
	nw3, err := nwtransport.SelectNowhereStack(options.ALPN)
	if err != nil {
		return nil, fmt.Errorf("nowhere %s: %w", options.Name(), err)
	}
	if nw3 {
		return nil, errNowhereDispatched
	}
	return newNowhereV2(options)
}

// errNowhereDispatched marks the Nowhere 3 path: NewNowhereV2 dispatches to
// NewNowhere, so reaching this error means the caller ignored the ALPN.
var errNowhereDispatched = errors.New("nowhere: Nowhere 3 must be built by NewNowhere")

func newNowhereV2(options *NowhereOption) (*NowhereV2, error) {
	if options.Password == "" {
		return nil, fmt.Errorf("nowhere %s: missing password", options.Name())
	}
	// The Portal admission rule (Rust Credentials::for_portal): the listener
	// key and every enabled next-hop key must be 32–64 lowercase hexadecimal
	// characters after URL percent decoding. Client-side keys stay lenient.
	password, err := decodeNowherePortalKey("password", options.Password, options.Name())
	if err != nil {
		return nil, err
	}
	options.Password = password
	if (options.Certificate == "") != (options.PrivateKey == "") {
		return nil, fmt.Errorf("nowhere %s: certificate and private-key must be set together (omit both for an in-memory self-signed certificate)", options.Name())
	}
	// NewNowhereV2 already rejected an omitted value and alpn nw3. This stack
	// accepts only the canonical Nowhere 2 protocol name.
	if len(options.ALPN) != 1 || options.ALPN[0] != nwtransport.DefaultALPN {
		return nil, fmt.Errorf("nowhere %s: alpn must be nw2", options.Name())
	}
	if options.Net != "" {
		return nil, fmt.Errorf("nowhere %s: net is a Nowhere 3 option; remove it or omit alpn", options.Name())
	}
	if err := validateNowhereNext(options.Name(), options.Next); err != nil {
		return nil, err
	}
	morph := nwtransport.ResolveNowhereMorph(options.Morph, false)
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &NowhereV2{
		Base:   base,
		config: options,
		ts: LC.NowhereServerV2{
			Enable:               true,
			Listen:               base.RawAddress(),
			Password:             options.Password,
			Certificate:          options.Certificate,
			PrivateKey:           options.PrivateKey,
			EchKey:               options.EchKey,
			ALPN:                 options.ALPN,
			CongestionController: options.CongestionController,
			CWND:                 options.CWND,
			Morph:                morph,
			Next:                 nowhereNextConfig(options.Next, morph),
		},
	}, nil
}

// validateNowhereNext checks the next-hop Portal section, mirroring the
// outbound's carrier/pool/pin rules (adapter/outbound/nowhere_v2.go).
func validateNowhereNext(name string, next *NowhereNextOption) error {
	if next == nil {
		return nil
	}
	if next.Server == "" {
		return fmt.Errorf("nowhere %s: next: missing server", name)
	}
	// Rust parses the port as u16.
	if next.Port <= 0 || next.Port > 65535 {
		return fmt.Errorf("nowhere %s: next: invalid port %d", name, next.Port)
	}
	if next.Password == "" {
		return fmt.Errorf("nowhere %s: next: missing password", name)
	}
	// The Portal admission rule applies to every hop, including next.
	decoded, err := decodeNowherePortalKey("next: password", next.Password, name)
	if err != nil {
		return err
	}
	next.Password = decoded
	if _, err := nwtransport.ResolveRoutePolicy(nwtransport.RouteInputs{
		Prefix: fmt.Sprintf("nowhere %s: next", name),
		Up:     next.Up,
		Down:   next.Down,
		Pool:   next.Pool,
		Mux:    next.Mux,
		Warn: func(format string, args ...any) {
			log.Warnln("[Nowhere](%s) next "+format, append([]any{name}, args...)...)
		},
	}); err != nil {
		return err
	}
	if _, err := nwtransport.ParseDialPolicy("", next.Dial4, next.Dial6); err != nil {
		return fmt.Errorf("nowhere %s: next: %w", name, err)
	}
	// Rust contract (vector/config.rs): the literal "none" is an alias for an
	// omitted sni/pin.
	if sni := normalizeNowhereNone(next.SNI); sni != "" && !validNowhereSNI(sni) {
		return fmt.Errorf("nowhere %s: next: sni must be an ASCII DNS name", name)
	}
	if pin := normalizeNowhereNone(next.Pin); pin != "" {
		if _, err := nwtransport.ParseCertificatePin(pin); err != nil {
			return fmt.Errorf("nowhere %s: next: %w", name, err)
		}
	}
	return nil
}

// normalizeNowhereNone maps the Rust "none" sentinel for sni/pin onto the
// empty value, which the listener config treats as unset.
func normalizeNowhereNone(value string) string {
	if value == "none" {
		return ""
	}
	return value
}

// nowherePortalKeyMinLen and nowherePortalKeyMaxLen bound the Portal shared-key
// text. Odd lengths inside the range are accepted.
const (
	nowherePortalKeyMinLen = 32
	nowherePortalKeyMaxLen = 64
)

// decodeNowherePortalKey enforces the Portal key admission rule (Rust
// Credentials::for_portal and docs/configuration.md "Shared keys"): after URL
// percent decoding the key must be 32–64 lowercase hexadecimal characters.
// Uppercase letters, non-hex characters, whitespace and other lengths fail
// before certificate loading, DNS resolution or listening. The decoded text
// bytes are the authentication and Morph derivation input — there is no hex
// decoding — so the decoded value is what the listener keeps.
func decodeNowherePortalKey(field, key, name string) (string, error) {
	decoded, err := url.PathUnescape(key)
	if err != nil {
		return "", fmt.Errorf("nowhere %s: %s: malformed percent escape in shared key", name, field)
	}
	if len(decoded) < nowherePortalKeyMinLen || len(decoded) > nowherePortalKeyMaxLen {
		return "", nowherePortalKeyError(name, field)
	}
	for i := 0; i < len(decoded); i++ {
		c := decoded[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", nowherePortalKeyError(name, field)
		}
	}
	return decoded, nil
}

func nowherePortalKeyError(name, field string) error {
	return fmt.Errorf("nowhere %s: %s: shared key must be %d–%d lowercase hexadecimal characters (openssl rand -hex %d is a quick way to make one)",
		name, field, nowherePortalKeyMinLen, nowherePortalKeyMaxLen, nowherePortalKeyMinLen/2)
}

// validNowhereSNI mirrors the Rust sni rule (vector/config.rs): an explicit
// sni must be an ASCII DNS name — at most 253 bytes, no ':'/'['/']', and not
// an IP literal.
func validNowhereSNI(sni string) bool {
	if len(sni) > 253 || strings.ContainsAny(sni, ":[]") {
		return false
	}
	for i := 0; i < len(sni); i++ {
		if sni[i] > 0x7f {
			return false
		}
	}
	if _, err := netip.ParseAddr(sni); err == nil {
		return false
	}
	return true
}

// nowhereNextConfig maps the inbound next option onto the listener server
// config; nil stays nil (direct tunnel upstream). sni/pin are normalized so
// NowhereNextV2 stores the effective values ("none" means unset).
func nowhereNextConfig(o *NowhereNextOption, inboundMorph bool) *LC.NowhereNextV2 {
	if o == nil {
		return nil
	}
	morph := inboundMorph
	if o.Morph != nil {
		morph = *o.Morph
	}
	return &LC.NowhereNextV2{
		Server:   o.Server,
		Port:     o.Port,
		Password: o.Password,
		Up:       o.Up,
		Down:     o.Down,
		Mux:      o.Mux,
		Pool:     o.Pool,
		Dial4:    o.Dial4,
		Dial6:    o.Dial6,
		SNI:      normalizeNowhereNone(o.SNI),
		Pin:      normalizeNowhereNone(o.Pin),
		Morph:    morph,
	}
}

// Config implements constant.InboundListener
func (n *NowhereV2) Config() C.InboundConfig {
	return n.config
}

// Address implements constant.InboundListener
func (n *NowhereV2) Address() string {
	var addrList []string
	if n.l != nil {
		addrList = n.l.AddrList()
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (n *NowhereV2) Listen(tunnel C.Tunnel) error {
	var err error
	n.l, err = nowhere.NewV2(n.ts, n.ListenConfig(), tunnel, n.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Nowhere[%s] proxy listening at: %s", n.Name(), n.Address())
	return nil
}

// Close implements constant.InboundListener
func (n *NowhereV2) Close() error {
	if n.l == nil {
		return nil
	}
	return n.l.Close()
}

var _ C.InboundListener = (*NowhereV2)(nil)

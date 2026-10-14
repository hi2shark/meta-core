package config

import (
	"encoding/json"
)

type NowhereServerV2 struct {
	Enable               bool     `yaml:"enable" json:"enable"`
	Listen               string   `yaml:"listen" json:"listen"`
	Password             string   `yaml:"password" json:"password"`
	Certificate          string   `yaml:"certificate" json:"certificate"`
	PrivateKey           string   `yaml:"private-key" json:"private-key"`
	EchKey               string   `yaml:"ech-key" json:"ech-key"`
	ALPN                 []string `yaml:"alpn" json:"alpn,omitempty"`
	CongestionController string   `yaml:"congestion-controller" json:"congestion-controller,omitempty"`
	CWND                 int      `yaml:"cwnd" json:"cwnd,omitempty"`
	// Morph enables the Nowhere 2 keyed socket transform below TLS/QUIC
	// (official CLI morph=1). There is no negotiation: the peer must match.
	Morph bool           `yaml:"morph" json:"morph,omitempty"`
	Next  *NowhereNextV2 `yaml:"next" json:"next,omitempty"`
}

// NowhereNextV2 is the next-hop Portal for native Portal chaining: when set,
// the listener forwards every inbound flow to another Nowhere 2 Portal instead
// of the tunnel. The forwarding connection inherits the listener ALPN and
// congestion-controller/cwnd. The next Portal must run Nowhere 2.
type NowhereNextV2 struct {
	Server   string `yaml:"server" json:"server"`
	Port     int    `yaml:"port" json:"port"`
	Password string `yaml:"password" json:"password"`
	// Up and Down independently select the carrier towards the next Portal
	// ("tcp" or "udp"). Each defaults to "udp" and they must be set together.
	Up   string `yaml:"up" json:"up,omitempty"`
	Down string `yaml:"down" json:"down,omitempty"`
	// Mux selects dedicated TLS lanes (0, default) or marked Mux shards (1)
	// towards the next Portal. udp/udp&mux=1 canonicalizes to 0.
	Mux *int `yaml:"mux" json:"mux,omitempty"`
	// Pool is the warm TLS/TCP connection count, only meaningful for dedicated
	// (mux=0) tcp/tcp (default 5 there, 0 otherwise; max tcptls.MaxPoolSize).
	Pool *int `yaml:"pool" json:"pool,omitempty"`
	// Dial4 is the IPv4 source address used towards the next Portal, or
	// "auto". See transport/nowhere.DialPolicy.
	Dial4 string `yaml:"dial4" json:"dial4,omitempty"`
	// Dial6 is the IPv6 source address used towards the next Portal, or
	// "auto". See transport/nowhere.DialPolicy.
	Dial6 string `yaml:"dial6" json:"dial6,omitempty"`
	// SNI overrides the TLS server name used towards the next Portal. Empty or
	// the literal "none" disables certificate verification (a domain server is
	// still sent as ClientHello SNI); an explicit DNS name enables chain+name
	// verification.
	SNI string `yaml:"sni" json:"sni,omitempty"`
	// Pin is the next Portal's leaf-certificate SHA-256 (lowercase hex). When
	// set (non-empty, non-"none") it overrides SNI/chain verification, like
	// the outbound's pin.
	Pin string `yaml:"pin" json:"pin,omitempty"`
	// Morph enables Morph towards the next Portal using next.password.
	// The inbound option layer copies the listener morph flag here when
	// next.morph is omitted (official portal:// morph=1 controls both hops).
	Morph bool `yaml:"morph" json:"morph,omitempty"`
}

func (n NowhereServerV2) String() string {
	b, _ := json.Marshal(n)
	return string(b)
}

// NowhereServer is the Nowhere 3 (nw3) Portal listener configuration. The
// vendored Portal owns its own handshake, so — unlike the Nowhere 2 server —
// there is no next-hop chaining, no ECH key and no admission-limit knob: ALPN
// is pinned to nw3 and TLS to 1.3.
type NowhereServer struct {
	Enable               bool   `yaml:"enable" json:"enable"`
	Listen               string `yaml:"listen" json:"listen"`
	Password             string `yaml:"password" json:"password"`
	Certificate          string `yaml:"certificate" json:"certificate"`
	PrivateKey           string `yaml:"private-key" json:"private-key"`
	CongestionController string `yaml:"congestion-controller" json:"congestion-controller,omitempty"`
	CWND                 int    `yaml:"cwnd" json:"cwnd,omitempty"`
	// Net is the single Nowhere 3 transport: tcp (TLS over TCP) or udp (QUIC).
	Net string `yaml:"net" json:"net,omitempty"`
	// Egress turns the Portal into an exit bridge: it accepts a single Egress
	// registration over QUIC (see NowhereEgress) and forwards every
	// authenticated flow there instead of to the local tunnel. It requires
	// net udp, because the registration handshake only exists there.
	Egress bool `yaml:"egress" json:"egress,omitempty"`
	// Morph enables the Nowhere 3 keyed transform below TLS/QUIC. The inbound
	// option layer resolves the per-stack default (off for Nowhere 2, on for
	// Nowhere 3).
	Morph bool `yaml:"morph" json:"morph,omitempty"`
}

func (n NowhereServer) String() string {
	b, _ := json.Marshal(n)
	return string(b)
}

// NowhereEgress is the Nowhere 3 Egress exit configuration. It never listens:
// it dials a Portal over QUIC, registers as that Portal's single exit, and
// serves the flows the Portal opens through the tunnel.
type NowhereEgress struct {
	Enable               bool   `yaml:"enable" json:"enable"`
	Server               string `yaml:"server" json:"server"`
	Port                 int    `yaml:"port" json:"port"`
	Password             string `yaml:"password" json:"password"`
	SNI                  string `yaml:"sni" json:"sni,omitempty"`
	Pin                  string `yaml:"pin" json:"pin,omitempty"`
	SkipCertVerify       bool   `yaml:"skip-cert-verify" json:"skip-cert-verify,omitempty"`
	CongestionController string `yaml:"congestion-controller" json:"congestion-controller,omitempty"`
	CWND                 int    `yaml:"cwnd" json:"cwnd,omitempty"`
	// Morph enables the Nowhere 3 keyed transform below QUIC towards the Portal.
	Morph bool `yaml:"morph" json:"morph,omitempty"`
}

func (n NowhereEgress) String() string {
	b, _ := json.Marshal(n)
	return string(b)
}

package nowhere

import (
	"crypto/x509"
	"fmt"
	"net/netip"

	"github.com/metacubex/mihomo/transport/nowhere/core/morph"
	nw2wire "github.com/metacubex/mihomo/transport/nowhere/core/nw2/wire"
	"github.com/metacubex/mihomo/transport/nowhere/core/wire"
)

// SelectNowhereStack reports which protocol stack one endpoint runs. An omitted
// ALPN, or a single value of NowhereALPN, selects Nowhere 3. Exactly nw2
// selects Nowhere 2. An empty name, more than one name, or any other protocol
// name is rejected.
func SelectNowhereStack(alpn []string) (nw3 bool, err error) {
	if len(alpn) == 0 {
		return true, nil
	}
	if len(alpn) != 1 {
		return false, errNowhereALPNCount()
	}
	if length := len(alpn[0]); length == 0 || length > 255 {
		return false, errNowhereALPNLength(length)
	}
	switch alpn[0] {
	case NowhereALPN:
		return true, nil
	case nw2wire.DefaultALPN:
		return false, nil
	default:
		return false, errNowhereALPNName(alpn[0])
	}
}

// ResolveNowhereMorph applies the per-stack Morph default: Nowhere 2 leaves the
// transform off, Nowhere 3 turns it on. An explicit value always wins.
func ResolveNowhereMorph(raw *bool, nw3 bool) bool {
	if raw != nil {
		return *raw
	}
	return nw3
}

// Nowhere 3 speaks exactly one transport per endpoint. tcp is TLS over TCP and
// udp is QUIC. Empty means tcp.
const (
	NowhereNetTCP = "tcp"
	NowhereNetUDP = "udp"
)

// NowhereNet resolves the single Nowhere 3 transport.
func NowhereNet(raw string) (string, error) {
	switch raw {
	case "", NowhereNetTCP:
		return NowhereNetTCP, nil
	case NowhereNetUDP:
		return NowhereNetUDP, nil
	default:
		return "", errNowhereNet(raw)
	}
}

// NowhereALPN is the only protocol identifier an nw3 carrier offers or
// accepts. The vendored stack pins it and never negotiates or falls back.
const NowhereALPN = wire.ALPN

// ValidateNowhereServiceKey enforces the nw3 shared-key rule: exactly 32
// lowercase hexadecimal characters. Nowhere 2 accepts 32–64, so the check has
// to live at the nw3 boundary rather than in the shared credential helper.
func ValidateNowhereServiceKey(key string) error {
	return wire.ValidateServiceKey(key)
}

// Nw3Target is a Nowhere 3 destination. Port zero is invalid.
type Nw3Target = wire.Target

// NewNw3IPTarget constructs an IP target. IPv4-mapped IPv6 addresses are
// rejected.
func NewNw3IPTarget(addr netip.Addr, port uint16) (Nw3Target, error) {
	return wire.NewIPTarget(addr, port)
}

// NewNw3DomainTarget constructs an ASCII/IDNA domain target.
func NewNw3DomainTarget(host string, port uint16) (Nw3Target, error) {
	return wire.NewDomainTarget(host, port)
}

// Nw3MorphKeys derives the Nowhere 3 Morph keys from the shared key. The nw2
// and nw3 key schedules are different, so the nw2 helper must not be reused
// here. The result is only needed for the QUIC carrier: the TCP carrier is
// wrapped inside the vendored Vector/Portal.
func Nw3MorphKeys(password string) *morph.Keys {
	keys := morph.Derive([]byte(password))
	return &keys
}

// Nw3PeerCertificatePinVerifier builds a leaf-certificate pin verifier for the
// nw3 client TLS config. A pin is a plain SHA-256 over the DER leaf, so the
// nw2 wire helpers are reused as-is.
func Nw3PeerCertificatePinVerifier(pin string) (func([][]byte, [][]*x509.Certificate) error, error) {
	return nw2wire.PeerCertificatePinVerifier(pin)
}

// Nw3ParseCertificatePin normalizes a pin value: empty or the literal "none"
// disables pinning, a real pin is validated here so a bad value fails at
// construction instead of the first dial.
func Nw3ParseCertificatePin(pin string) (string, error) {
	return nw2wire.ParseCertificatePin(pin)
}

// Nw3LeafCertificateSHA256Hex renders a leaf certificate as the lowercase hex
// users copy into a pin= value.
func Nw3LeafCertificateSHA256Hex(raw []byte) string {
	return nw2wire.LeafCertificateSHA256Hex(raw)
}

func errNowhereALPNCount() error {
	return fmt.Errorf("nowhere: alpn must contain exactly one value")
}

func errNowhereALPNLength(length int) error {
	return fmt.Errorf("nowhere: invalid alpn length %d", length)
}

func errNowhereALPNName(name string) error {
	return fmt.Errorf("nowhere: alpn must be nw3 or nw2, got %q", name)
}

func errNowhereNet(raw string) error {
	return fmt.Errorf("nowhere: net must be %s or %s, got %q", NowhereNetTCP, NowhereNetUDP, raw)
}

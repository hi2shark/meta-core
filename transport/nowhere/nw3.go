package nowhere

import (
	"crypto/x509"
	"fmt"
	"net/netip"

	"github.com/metacubex/mihomo/transport/nowhere/core/morph"
	nw2wire "github.com/metacubex/mihomo/transport/nowhere/core/nw2/wire"
	"github.com/metacubex/mihomo/transport/nowhere/core/wire"
)

// Nowhere 3 (nw3) stack selection. The two stacks share no handshake: one
// endpoint runs exactly one version, and the nw2-only fields are rejected when
// version 3 is selected. Nowhere 2 keeps working unchanged because an omitted
// version resolves to 2.
const (
	NowhereVersion2 = 2
	NowhereVersion3 = 3
)

// ResolveNowhereVersion maps the raw version option to a stack. Empty means 2,
// which keeps every pre-nw3 configuration working unchanged.
func ResolveNowhereVersion(raw int) (int, error) {
	switch raw {
	case 0, NowhereVersion2:
		return NowhereVersion2, nil
	case NowhereVersion3:
		return NowhereVersion3, nil
	default:
		return 0, errNowhereVersion(raw)
	}
}

// ResolveNowhereMorph applies the per-version Morph default: Nowhere 2 leaves
// the transform off, Nowhere 3 turns it on. An explicit value always wins.
func ResolveNowhereMorph(raw *bool, version int) bool {
	if raw != nil {
		return *raw
	}
	return version == NowhereVersion3
}

// Nowhere 3 speaks exactly one transport per endpoint: tcp (TLS over TCP) or
// quic. Empty means tcp.
const (
	NowhereV3CarrierTCP  = "tcp"
	NowhereV3CarrierQUIC = "quic"
)

// NowhereV3Carrier resolves the single Nowhere 3 carrier.
func NowhereV3Carrier(raw string) (string, error) {
	switch raw {
	case "", NowhereV3CarrierTCP:
		return NowhereV3CarrierTCP, nil
	case NowhereV3CarrierQUIC:
		return NowhereV3CarrierQUIC, nil
	default:
		return "", errNowhereV3Carrier(raw)
	}
}

// NowhereV3ALPN is the only protocol identifier an nw3 carrier offers or
// accepts. The vendored stack pins it and never negotiates or falls back.
const NowhereV3ALPN = wire.ALPN

// ValidateNowhereV3ServiceKey enforces the nw3 shared-key rule: exactly 32
// lowercase hexadecimal characters. Nowhere 2 accepts 32–64, so the check has
// to live at the nw3 boundary rather than in the shared credential helper.
func ValidateNowhereV3ServiceKey(key string) error {
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

func errNowhereVersion(raw int) error {
	return fmt.Errorf("nowhere: version must be %d or %d, got %d", NowhereVersion2, NowhereVersion3, raw)
}

func errNowhereV3Carrier(raw string) error {
	return fmt.Errorf("nowhere: version %d carrier must be %s or %s, got %q", NowhereVersion3, NowhereV3CarrierTCP, NowhereV3CarrierQUIC, raw)
}

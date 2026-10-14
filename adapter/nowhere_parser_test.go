package adapter

import (
	"strings"
	"testing"
)

// TestParseNowhereProxy drives the public ParseProxy entry point to confirm the
// "nowhere" type is wired into the registry and produces a C.Nowhere proxy.
func TestParseNowhereProxy(t *testing.T) {
	// An omitted ALPN selects Nowhere 3, which requires a 32-hex key.
	mapping := map[string]any{
		"type":     "nowhere",
		"name":     "nw",
		"server":   "example.com",
		"port":     2077,
		"password": "0123456789abcdef0123456789abcdef",
	}
	proxy, err := ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy: %v", err)
	}
	if proxy.Type().String() != "Nowhere" {
		t.Fatalf("type = %q, want Nowhere", proxy.Type().String())
	}
	if !proxy.SupportUDP() {
		t.Fatalf("SupportUDP = false, want true when udp key omitted")
	}
	if _, err := ParseProxy(map[string]any{
		"type": "nowhere", "name": "nw", "server": "example.com",
		"port": 2077, "password": "secret",
	}); err == nil {
		t.Fatal("ParseProxy accepted a non-32-hex key on the default Nowhere 3 stack")
	}

	// up/down select the Nowhere 2 carrier matrix and require alpn nw2.
	upDownMapping := map[string]any{
		"type":     "nowhere",
		"name":     "nw-tcp",
		"server":   "example.com",
		"port":     2077,
		"password": "secret",
		"alpn":     []string{"nw2"},
		"up":       "tcp",
		"down":     "tcp",
	}
	if _, err := ParseProxy(upDownMapping); err != nil {
		t.Fatalf("ParseProxy up/down: %v", err)
	}

	// An unknown carrier value must be rejected at parse time.
	badMapping := map[string]any{
		"type": "nowhere", "name": "nw", "server": "example.com",
		"port": 2077, "password": "secret", "alpn": []string{"nw2"},
		"up": "carrier-pigeon", "down": "udp",
	}
	if _, err := ParseProxy(badMapping); err == nil {
		t.Fatalf("ParseProxy accepted invalid carrier")
	}

	// A missing shared secret must be rejected.
	noPasswordMapping := map[string]any{
		"type": "nowhere", "name": "nw", "server": "example.com", "port": 2077,
	}
	if _, err := ParseProxy(noPasswordMapping); err == nil {
		t.Fatalf("ParseProxy accepted missing password")
	}

	// The legacy key/network/net aliases are gone: a mapping that only sets
	// them decodes with an empty password and must be rejected.
	legacyMapping := map[string]any{
		"type": "nowhere", "name": "nw-legacy", "server": "example.com",
		"port": 2077, "key": "secret", "network": "udp",
	}
	if _, err := ParseProxy(legacyMapping); err == nil {
		t.Fatalf("ParseProxy accepted legacy key/network aliases")
	}

	udpDisabledMapping := map[string]any{
		"type": "nowhere", "name": "nw", "server": "example.com",
		"port": 2077, "password": "0123456789abcdef0123456789abcdef", "udp": false,
	}
	udpDisabled, err := ParseProxy(udpDisabledMapping)
	if err != nil {
		t.Fatalf("ParseProxy udp disabled: %v", err)
	}
	if udpDisabled.SupportUDP() {
		t.Fatalf("SupportUDP = true, want false when udp: false")
	}

	mixMapping := map[string]any{
		"type": "nowhere", "name": "nw-mix", "server": "example.com",
		"port": 2077, "password": "secret", "alpn": []string{"nw2"},
		"up": "mix", "down": "mix", "mux": 1,
	}
	// mix is not a carrier since Nowhere 2.2: up/down must be tcp or udp.
	if _, err := ParseProxy(mixMapping); err == nil {
		t.Fatalf("ParseProxy accepted mix carrier")
	} else if !strings.Contains(err.Error(), "must be tcp or udp") {
		t.Fatalf("ParseProxy mix error = %v, want \"must be tcp or udp\"", err)
	}

	morphMapping := map[string]any{
		"type": "nowhere", "name": "nw-morph", "server": "example.com",
		"port": 2077, "password": "secret", "alpn": []string{"nw2"}, "morph": 1,
	}
	if _, err := ParseProxy(morphMapping); err != nil {
		t.Fatalf("ParseProxy morph: %v", err)
	}
	if _, err := ParseProxy(map[string]any{
		"type": "nowhere", "name": "nw-net", "server": "example.com",
		"port": 2077, "password": "secret", "alpn": []string{"nw2"}, "net": "udp",
	}); err == nil {
		t.Fatal("ParseProxy accepted net on the Nowhere 2 stack")
	}
	if _, err := ParseProxy(map[string]any{
		"type": "nowhere", "name": "nw-quic", "server": "example.com",
		"port": 2077, "password": "0123456789abcdef0123456789abcdef", "net": "quic",
	}); err == nil {
		t.Fatal("ParseProxy accepted net quic")
	}
}

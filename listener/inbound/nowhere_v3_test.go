package inbound_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/log"
)

// testNw3Key is a Nowhere 3 service key: exactly 32 lowercase hexadecimal
// characters. The nw2 keys in nowhere_test.go are deliberately not reused here:
// the two stacks have different key rules and must not be mixed.
const testNw3Key = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

// testNw2Key is a Portal-admissible Nowhere 2 key: 32 lowercase hexadecimal
// characters. It is deliberately longer than the Nowhere 3 rule allows, so it
// doubles as the "wrong length" case for the nw3 validators.
const testNw2Key = "0123456789abcdef0123456789abcdef01234567"

func nw3BaseOption() inbound.BaseOption {
	return inbound.BaseOption{NameStr: "nowhere-nw3", Listen: "127.0.0.1", Port: "0"}
}

func TestParseListenerNowhereVersion(t *testing.T) {
	t.Run("omitted version stays nw2", func(t *testing.T) {
		parsed, err := listener.ParseListener(map[string]any{
			"type": "nowhere", "name": "nowhere-nw2", "listen": "127.0.0.1", "port": 0, "password": testNw2Key,
		})
		if err != nil {
			t.Fatalf("ParseListener: %v", err)
		}
		if _, ok := parsed.Config().(*inbound.NowhereOption); !ok {
			t.Fatalf("Config() = %T, want *inbound.NowhereOption", parsed.Config())
		}
	})
	t.Run("version 2 stays nw2", func(t *testing.T) {
		parsed, err := listener.ParseListener(map[string]any{
			"type": "nowhere", "name": "nowhere-nw2", "listen": "127.0.0.1", "port": 0, "password": testNw2Key, "version": 2,
		})
		if err != nil {
			t.Fatalf("ParseListener: %v", err)
		}
		if _, ok := parsed.Config().(*inbound.NowhereOption); !ok {
			t.Fatalf("Config() = %T, want *inbound.NowhereOption", parsed.Config())
		}
	})
	t.Run("version 3 selects nw3", func(t *testing.T) {
		parsed, err := listener.ParseListener(map[string]any{
			"type": "nowhere", "name": "nowhere-nw3", "listen": "127.0.0.1", "port": 0, "password": testNw3Key, "version": 3,
		})
		if err != nil {
			t.Fatalf("ParseListener: %v", err)
		}
		// The v3 inbound reuses the shared NowhereOption; what selects the stack
		// is the resolved Version, which ParseListener dispatches on.
		options, ok := parsed.Config().(*inbound.NowhereOption)
		if !ok {
			t.Fatalf("Config() = %T, want *inbound.NowhereOption", parsed.Config())
		}
		if options.Version != 3 {
			t.Fatalf("Version = %d, want 3", options.Version)
		}
		if _, ok := parsed.(*inbound.NowhereV3); !ok {
			t.Fatalf("parsed = %T, want *inbound.NowhereV3", parsed)
		}
	})
	t.Run("unknown version fails", func(t *testing.T) {
		if _, err := listener.ParseListener(map[string]any{
			"type": "nowhere", "name": "nowhere-nw5", "listen": "127.0.0.1", "port": 0, "password": testNw3Key, "version": 5,
		}); err == nil {
			t.Fatal("ParseListener(version: 5) = nil error, want a version error")
		}
	})
}

func TestNewNowhereV3RejectsUnsupportedFields(t *testing.T) {
	base := func() *inbound.NowhereOption {
		return &inbound.NowhereOption{BaseOption: nw3BaseOption(), Password: testNw3Key, Version: 3}
	}
	for name, mutate := range map[string]func(*inbound.NowhereOption){
		"key":           func(o *inbound.NowhereOption) { o.Password = "xyz" },
		"key-length":    func(o *inbound.NowhereOption) { o.Password = testNw2Key },
		"carrier":       func(o *inbound.NowhereOption) { o.Carrier = "ws" },
		"next":          func(o *inbound.NowhereOption) { o.Next = &inbound.NowhereNextOption{} },
		"ech-key":       func(o *inbound.NowhereOption) { o.EchKey = "not-a-real-key" },
		"alpn":          func(o *inbound.NowhereOption) { o.ALPN = []string{"nw3"} },
		"egress-on-tcp": func(o *inbound.NowhereOption) { o.Egress = true },
	} {
		t.Run(name, func(t *testing.T) {
			options := base()
			mutate(options)
			if _, err := inbound.NewNowhereV3(options); err == nil {
				t.Fatalf("NewNowhereV3(%s) = nil error, want a rejection", name)
			}
		})
	}
	// The same fields on version 2 keep working, because the nw2 listener
	// still accepts next chaining, an ECH key and an explicit ALPN.
	options := base()
	options.Version = 0
	options.ALPN = []string{"nw2"}
	if _, err := inbound.NewNowhere(options); err != nil {
		t.Fatalf("NewNowhere with nw2 fields: %v", err)
	}
}

func TestNewNowhereEgressValidation(t *testing.T) {
	base := func() *inbound.NowhereEgressOption {
		return &inbound.NowhereEgressOption{
			BaseOption: inbound.BaseOption{NameStr: "nowhere-egress", Listen: "127.0.0.1", Port: "0"},
			Server:     "127.0.0.1", Port: 2080, Password: testNw3Key,
		}
	}
	for name, mutate := range map[string]func(*inbound.NowhereEgressOption){
		"password":   func(o *inbound.NowhereEgressOption) { o.Password = "" },
		"key":        func(o *inbound.NowhereEgressOption) { o.Password = "xyz" },
		"key-length": func(o *inbound.NowhereEgressOption) { o.Password = testNw2Key },
		"server":     func(o *inbound.NowhereEgressOption) { o.Server = "" },
		"port":       func(o *inbound.NowhereEgressOption) { o.Port = 0 },
		"port-range": func(o *inbound.NowhereEgressOption) { o.Port = 70000 },
		"pin":        func(o *inbound.NowhereEgressOption) { o.Pin = "not-a-pin" },
	} {
		t.Run(name, func(t *testing.T) {
			options := base()
			mutate(options)
			if _, err := inbound.NewNowhereEgress(options); err == nil {
				t.Fatalf("NewNowhereEgress(%s) = nil error, want a rejection", name)
			}
		})
	}
	// "none" is the Rust sentinel for an omitted sni/pin, and skip-cert-verify
	// is the documented insecure escape hatch.
	options := base()
	options.SNI = "none"
	options.Pin = "none"
	options.SkipCertVerify = true
	if _, err := inbound.NewNowhereEgress(options); err != nil {
		t.Fatalf("NewNowhereEgress with none sentinels: %v", err)
	}
}

func TestParseListenerNowhereEgress(t *testing.T) {
	parsed, err := listener.ParseListener(map[string]any{
		"type": "nowhere-egress", "name": "nowhere-egress", "listen": "127.0.0.1", "port": 0,
		"server": "portal.example.com", "server-port": 443, "password": testNw3Key,
	})
	if err != nil {
		t.Fatalf("ParseListener: %v", err)
	}
	options, ok := parsed.Config().(*inbound.NowhereEgressOption)
	if !ok {
		t.Fatalf("Config() = %T, want *inbound.NowhereEgressOption", parsed.Config())
	}
	if options.Server != "portal.example.com" || options.Port != 443 {
		t.Fatalf("egress portal = %s:%d, want portal.example.com:443", options.Server, options.Port)
	}
	if parsed.Address() != "" {
		t.Fatalf("Address() = %q, want empty (the Egress never listens)", parsed.Address())
	}
}

// recordingTunnel echoes every TCP flow and every UDP datagram back to the
// client and records what it saw, so a test can tell which side of an egress
// chain served a flow.
type recordingTunnel struct {
	tcp  chan string
	udp  chan string
	seen chan string
}

func newRecordingTunnel() *recordingTunnel {
	return &recordingTunnel{tcp: make(chan string, 8), udp: make(chan string, 8), seen: make(chan string, 16)}
}

func (r *recordingTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	r.record("tcp", metadata)
	defer func() { _ = conn.Close() }()
	_, _ = io.Copy(conn, conn)
}

func (r *recordingTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	r.record("udp", metadata)
	_, _ = packet.WriteBack(packet.Data(), nil)
}

func (r *recordingTunnel) NatTable() C.NatTable {
	return nil
}

func (r *recordingTunnel) record(kind string, metadata *C.Metadata) {
	select {
	case r.seen <- kind + " " + metadata.String():
	default:
	}
}

// dialNw3Flow retries one client dial until the Portal can serve it. The Egress
// registration is asynchronous (egress.Run owns its own reconnect loop), so a
// client that starts right after the exit may race the registration and be told
// the flow cannot be dialed. A real client sees the same window, and the retry
// below is what it takes to cross it.
func dialNw3Flow(ctx context.Context, client *outbound.NowhereV3, metadata *C.Metadata) (net.Conn, error) {
	for {
		conn, err := client.DialContext(ctx, metadata)
		if err == nil || ctx.Err() != nil {
			return conn, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// TestNowhereV3EgressForwarding wires the full Nowhere 3 exit chain: a Portal in
// egress mode (QUIC carrier), one Egress client registered to it, and one Vector
// client dialing the Portal. A flow must be served by the Egress side, never by
// the Portal's own tunnel.
func TestNowhereV3EgressForwarding(t *testing.T) {
	portalTunnel := newRecordingTunnel()
	egressTunnel := newRecordingTunnel()

	portal, err := inbound.NewNowhereV3(&inbound.NowhereOption{
		BaseOption: nw3BaseOption(),
		Password:   testNw3Key,
		Version:    3,
		Carrier:    "quic",
		Egress:     true,
	})
	if err != nil {
		t.Fatalf("NewNowhereV3 egress portal: %v", err)
	}
	if err := portal.Listen(portalTunnel); err != nil {
		t.Fatalf("portal Listen: %v", err)
	}
	defer func() { _ = portal.Close() }()
	_, portalPortStr, err := net.SplitHostPort(portal.Address())
	if err != nil {
		t.Fatalf("portal address %q: %v", portal.Address(), err)
	}
	portalPort, err := strconv.Atoi(portalPortStr)
	if err != nil {
		t.Fatalf("portal port %q: %v", portalPortStr, err)
	}

	egress, err := inbound.NewNowhereEgress(&inbound.NowhereEgressOption{
		BaseOption: inbound.BaseOption{NameStr: "nowhere-egress-test", Listen: "127.0.0.1", Port: "0"},
		Server:     "127.0.0.1", Port: portalPort, Password: testNw3Key,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("NewNowhereEgress: %v", err)
	}
	if err := egress.Listen(egressTunnel); err != nil {
		t.Fatalf("egress Listen: %v", err)
	}
	defer func() { _ = egress.Close() }()

	client, err := outbound.NewNowhereV3(outbound.NowhereOption{
		Name: "nowhere-nw3-egress-client", Server: "127.0.0.1", Port: portalPort,
		Password: testNw3Key, SkipCertVerify: true,
		Version: 3, Carrier: "quic", UDP: true,
	})
	if err != nil {
		t.Fatalf("NewNowhereV3 client: %v", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := dialNw3Flow(ctx, client, &C.Metadata{Host: "example.com", DstPort: 80})
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("nowhere nw3 egress echo")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo = %q, want %q", buf, payload)
	}

	select {
	case seen := <-egressTunnel.seen:
		if got := seen[:4]; got != "tcp " {
			t.Fatalf("egress tunnel saw %q, want a tcp flow", seen)
		}
	default:
		t.Fatal("egress tunnel served no flow")
	}
	select {
	case seen := <-portalTunnel.seen:
		t.Fatalf("portal tunnel served a flow it should have bridged: %q", seen)
	default:
	}
}

// TestNowhereV3EgressBusy checks the single-exit rule. A second Egress dialing
// the same Portal is told the exit is taken (egress.ErrBusy) and keeps
// retrying; it must not preempt the owner. Only after the owner goes away does
// the retry succeed, which is also what makes a restarted exit self-heal.
func TestNowhereV3EgressBusy(t *testing.T) {
	portalTunnel := newRecordingTunnel()
	ownerTunnel := newRecordingTunnel()
	waiterTunnel := newRecordingTunnel()

	// The busy rejection is only observable through the host's own warning, so
	// the test subscribes to the log stream to learn when the waiter has been
	// told the exit is taken.
	subscription := log.Subscribe()
	defer log.UnSubscribe(subscription)
	busy := make(chan struct{}, 1)
	go func() {
		for event := range subscription {
			if strings.Contains(event.Payload, "already has an exit registered") {
				select {
				case busy <- struct{}{}:
				default:
				}
				return
			}
		}
	}()

	portal, err := inbound.NewNowhereV3(&inbound.NowhereOption{
		BaseOption: nw3BaseOption(),
		Password:   testNw3Key,
		Version:    3,
		Carrier:    "quic",
		Egress:     true,
	})
	if err != nil {
		t.Fatalf("NewNowhereV3 egress portal: %v", err)
	}
	if err := portal.Listen(portalTunnel); err != nil {
		t.Fatalf("portal Listen: %v", err)
	}
	defer func() { _ = portal.Close() }()
	portalPort := nw3PortalPort(t, portal.Address())

	owner, err := newNw3TestEgress(t, "nw3-egress-owner", portalPort, ownerTunnel)
	if err != nil {
		t.Fatalf("NewNowhereEgress owner: %v", err)
	}

	client, err := outbound.NewNowhereV3(outbound.NowhereOption{
		Name: "nowhere-nw3-busy-client", Server: "127.0.0.1", Port: portalPort,
		Password: testNw3Key, SkipCertVerify: true,
		Version: 3, Carrier: "quic", UDP: true,
	})
	if err != nil {
		t.Fatalf("NewNowhereV3 client: %v", err)
	}
	defer func() { _ = client.Close() }()

	// The owner registers first and is serving before the second exit arrives,
	// so the race for the single registration is decided, not assumed.
	if err := echoOneFlow(t, client, ownerTunnel, "owner established"); err != nil {
		t.Fatalf("flow with the owner alone: %v", err)
	}
	if got := drainTunnelSeen(portalTunnel); got != "" {
		t.Fatalf("the portal tunnel served %q, want nothing", got)
	}

	// A second exit dials the same Portal: it is told the exit is taken and
	// keeps retrying, so the owner alone keeps serving every flow.
	waiter, err := newNw3TestEgress(t, "nw3-egress-waiter", portalPort, waiterTunnel)
	if err != nil {
		t.Fatalf("NewNowhereEgress waiter: %v", err)
	}
	defer func() { _ = waiter.Close() }()
	select {
	case <-busy:
	case <-time.After(15 * time.Second):
		t.Fatal("the waiter was never told the exit is taken")
	}
	if err := echoOneFlow(t, client, ownerTunnel, "while the waiter is busy"); err != nil {
		t.Fatalf("flow while the waiter is busy: %v", err)
	}
	if got := drainTunnelSeen(waiterTunnel); got != "" {
		t.Fatalf("the busy waiter served %q, want nothing", got)
	}
	if got := drainTunnelSeen(portalTunnel); got != "" {
		t.Fatalf("the portal tunnel served %q, want nothing", got)
	}

	// Dropping the owner releases the exit: the waiter's retry loop picks it up
	// after its cooldown and serves the next flow on its own.
	if err := owner.Close(); err != nil {
		t.Fatalf("owner Close: %v", err)
	}
	if err := echoOneFlow(t, client, waiterTunnel, "after handover"); err != nil {
		t.Fatalf("flow after handover: %v", err)
	}
}

// TestCleanupReleasesNowhereEgress guards the shutdown path. An Egress holds a
// live QUIC session to its Portal, and only closing the listener sends the
// CONNECTION_CLOSE that releases the exit. Without it a stopped Egress leaves
// the Portal's single exit pinned to a dead connection until the QUIC idle
// timeout expires, so no replacement exit can register in the meantime.
func TestCleanupReleasesNowhereEgress(t *testing.T) {
	portalTunnel := newRecordingTunnel()
	ownerTunnel := newRecordingTunnel()
	waiterTunnel := newRecordingTunnel()

	portal, err := inbound.NewNowhereV3(&inbound.NowhereOption{
		BaseOption: nw3BaseOption(),
		Password:   testNw3Key,
		Version:    3,
		Carrier:    "quic",
		Egress:     true,
	})
	if err != nil {
		t.Fatalf("NewNowhereV3 egress portal: %v", err)
	}
	if err := portal.Listen(portalTunnel); err != nil {
		t.Fatalf("portal Listen: %v", err)
	}
	defer func() { _ = portal.Close() }()
	portalPort := nw3PortalPort(t, portal.Address())

	// Registered the way the config path registers it, so Cleanup can find it.
	owner, err := inbound.NewNowhereEgress(&inbound.NowhereEgressOption{
		BaseOption: inbound.BaseOption{NameStr: "nw3-egress-shutdown", Listen: "127.0.0.1", Port: "0"},
		Server:     "127.0.0.1", Port: portalPort, Password: testNw3Key,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("NewNowhereEgress owner: %v", err)
	}
	listener.PatchInboundListeners(map[string]C.InboundListener{"nw3-egress-shutdown": owner}, ownerTunnel, false)
	t.Cleanup(func() { _ = owner.Close() })

	client, err := outbound.NewNowhereV3(outbound.NowhereOption{
		Name: "nowhere-nw3-shutdown-client", Server: "127.0.0.1", Port: portalPort,
		Password: testNw3Key, SkipCertVerify: true,
		Version: 3, Carrier: "quic", UDP: true,
	})
	if err != nil {
		t.Fatalf("NewNowhereV3 client: %v", err)
	}
	defer func() { _ = client.Close() }()

	if err := echoOneFlow(t, client, ownerTunnel, "before shutdown"); err != nil {
		t.Fatalf("flow before shutdown: %v", err)
	}

	listener.Cleanup()

	// The exit must be free now: a fresh Egress registers without being told the
	// exit is taken, and serves the next flow.
	waiter, err := newNw3TestEgress(t, "nw3-egress-shutdown-waiter", portalPort, waiterTunnel)
	if err != nil {
		t.Fatalf("NewNowhereEgress waiter: %v", err)
	}
	defer func() { _ = waiter.Close() }()
	if err := echoOneFlow(t, client, waiterTunnel, "after shutdown"); err != nil {
		t.Fatalf("flow after shutdown: %v", err)
	}
}

func newNw3TestEgress(t *testing.T, name string, portalPort int, tunnel *recordingTunnel) (*inbound.NowhereEgress, error) {
	t.Helper()
	egress, err := inbound.NewNowhereEgress(&inbound.NowhereEgressOption{
		BaseOption: inbound.BaseOption{NameStr: name, Listen: "127.0.0.1", Port: "0"},
		Server:     "127.0.0.1", Port: portalPort, Password: testNw3Key,
		SkipCertVerify: true,
	})
	if err != nil {
		return nil, err
	}
	if err := egress.Listen(tunnel); err != nil {
		_ = egress.Close()
		return nil, err
	}
	return egress, nil
}

func nw3PortalPort(t *testing.T, address string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("portal address %q: %v", address, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("portal port %q: %v", portStr, err)
	}
	return port
}

// echoOneFlow dials one flow and expects the echo to come back, then reports
// which tunnel served it. The dial retries because an exit registration is
// asynchronous and the handover above leaves a cooldown window.
func echoOneFlow(t *testing.T, client *outbound.NowhereV3, tunnel *recordingTunnel, stage string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := dialNw3Flow(ctx, client, &C.Metadata{Host: "example.com", DstPort: 80})
	if err != nil {
		return fmt.Errorf("dial %s: %w", stage, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	payload := []byte("nowhere nw3 egress " + stage)
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write %s: %w", stage, err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read %s: %w", stage, err)
	}
	if string(buf) != string(payload) {
		return fmt.Errorf("echo %s = %q, want %q", stage, buf, payload)
	}

	select {
	case seen := <-tunnel.seen:
		if got := seen[:4]; got != "tcp " {
			return fmt.Errorf("%s tunnel saw %q, want a tcp flow", stage, seen)
		}
	default:
		return fmt.Errorf("%s tunnel served no flow", stage)
	}
	return nil
}

func drainTunnelSeen(tunnel *recordingTunnel) string {
	select {
	case seen := <-tunnel.seen:
		return seen
	default:
		return ""
	}
}

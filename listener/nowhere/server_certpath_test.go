package nowhere_test

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	nwlisten "github.com/metacubex/mihomo/listener/nowhere"
	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
)

// writeTestCertFiles writes the shared inline test pair to disk in the panel's
// per-cert layout (certs/<id>/fullchain.pem + key.pem) and returns the base
// directory plus the pair of absolute paths.
func writeTestCertFiles(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs", "cert-1")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	certPath := filepath.Join(certDir, "fullchain.pem")
	keyPath := filepath.Join(certDir, "key.pem")
	if err := os.WriteFile(certPath, []byte(testCertificate), 0o644); err != nil {
		t.Fatalf("write fullchain.pem: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(testPrivateKey), 0o600); err != nil {
		t.Fatalf("write key.pem: %v", err)
	}
	return dir, certPath, keyPath
}

// setTestHomeDir points the global home dir at dir for the test's duration:
// production agents run the core with the home dir at the data dir the
// rendered certificate paths live under, so the safety check passes there.
func setTestHomeDir(t *testing.T, dir string) {
	t.Helper()
	previous := C.Path.HomeDir()
	C.SetHomeDir(dir)
	t.Cleanup(func() { C.SetHomeDir(previous) })
}

// startNw3TestServerWithCerts is startNw3TestServer with an explicit
// certificate/private-key pair, so file-path forms reuse the same harness.
func startNw3TestServerWithCerts(t *testing.T, netName, certificate, privateKey string) int {
	t.Helper()
	server, err := nwlisten.New(LC.NowhereServer{
		Enable:               true,
		Listen:               "127.0.0.1:0",
		Password:             testNw3Password,
		Certificate:          certificate,
		PrivateKey:           privateKey,
		CongestionController: "bbr",
		Net:                  netName,
		Morph:                true,
	}, inbound.NewListenConfig(), fakeTunnel{})
	if err != nil {
		t.Fatalf("nowhere.New with certificate %q: %v", certificate, err)
	}
	t.Cleanup(func() { _ = server.Close() })

	addrList := server.AddrList()
	if len(addrList) != 1 {
		t.Fatalf("AddrList = %v, want one address", addrList)
	}
	_, portStr, err := net.SplitHostPort(addrList[0])
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addrList[0], err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}
	return port
}

// TestNowhereV3CertificateFromRelativeFilePaths covers the exec-core rendering:
// the config references the pair relative to the core's home dir.
func TestNowhereV3CertificateFromRelativeFilePaths(t *testing.T) {
	dir, _, _ := writeTestCertFiles(t)
	setTestHomeDir(t, dir)
	port := startNw3TestServerWithCerts(t, nwtransport.NowhereNetTCP,
		"certs/cert-1/fullchain.pem", "certs/cert-1/key.pem")
	testNw3Forwarding(t, newNw3TestClient(t, port, nwtransport.NowhereNetTCP, true))
}

// TestNowhereV3CertificateFromAbsoluteFilePaths covers the embedded rendering:
// the agent absolutizes the pair under the data dir before applying it.
func TestNowhereV3CertificateFromAbsoluteFilePaths(t *testing.T) {
	dir, certPath, keyPath := writeTestCertFiles(t)
	setTestHomeDir(t, dir)
	port := startNw3TestServerWithCerts(t, nwtransport.NowhereNetTCP, certPath, keyPath)
	testNw3Forwarding(t, newNw3TestClient(t, port, nwtransport.NowhereNetTCP, true))
}

// TestNowhereV3CertificateMissingFilesError keeps the failure diagnosable: a
// pair pointing at absent files reports the path error next to the inline one.
func TestNowhereV3CertificateMissingFilesError(t *testing.T) {
	setTestHomeDir(t, t.TempDir())
	_, err := nwlisten.New(LC.NowhereServer{
		Enable:      true,
		Listen:      "127.0.0.1:0",
		Password:    testNw3Password,
		Certificate: "certs/gone/fullchain.pem",
		PrivateKey:  "certs/gone/key.pem",
		Net:         nwtransport.NowhereNetTCP,
	}, inbound.NewListenConfig(), fakeTunnel{})
	if err == nil {
		t.Fatal("nowhere.New with missing cert files = nil error, want a path error")
	}
	if !strings.Contains(err.Error(), "path error") {
		t.Fatalf("nowhere.New error = %v, want it to mention the path error", err)
	}
}

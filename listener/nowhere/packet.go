package nowhere

import (
	stdtls "crypto/tls"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/fswatch"
)

// newStdTLSKeyPairLoader parses a PEM pair once and hands out the same
// certificate for every handshake. The vendored Portal performs its own
// standard-library handshakes, so it cannot use Mihomo's metacubex/tls loader.
// Like ca.NewTLSKeyPairLoader, the pair accepts inline PEM or file paths:
// inline parsing runs first, then the pair loads from disk and is reloaded
// when the files change (certificate renewal rewrites them in place).
func newStdTLSKeyPairLoader(certificate, privateKey string) (func() (*stdtls.Certificate, error), error) {
	cert, inlineErr := stdtls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if inlineErr == nil {
		return func() (*stdtls.Certificate, error) {
			return &cert, nil
		}, nil
	}

	certPath := C.Path.Resolve(certificate)
	keyPath := C.Path.Resolve(privateKey)
	var loadErr error
	if !C.Path.IsSafePath(certPath) {
		loadErr = C.Path.ErrNotSafePath(certPath)
	} else if !C.Path.IsSafePath(keyPath) {
		loadErr = C.Path.ErrNotSafePath(keyPath)
	} else {
		cert, loadErr = stdtls.LoadX509KeyPair(certPath, keyPath)
	}
	if loadErr != nil {
		return nil, fmt.Errorf("parse certificate failed, maybe format error:%s, or path error: %s", inlineErr.Error(), loadErr.Error())
	}
	gcFlag := new(os.File) // tiny (on the order of 16 bytes or less) and pointer-free objects may never run the finalizer, so we choose new an os.File
	updateMutex := sync.RWMutex{}
	if watcher, err := fswatch.NewWatcher(fswatch.Options{Path: []string{certPath, keyPath}, Callback: func(path string) {
		updateMutex.Lock()
		defer updateMutex.Unlock()
		if newCert, err := stdtls.LoadX509KeyPair(certPath, keyPath); err == nil {
			cert = newCert
		}
	}}); err == nil {
		if err = watcher.Start(); err == nil {
			runtime.SetFinalizer(gcFlag, func(f *os.File) {
				_ = watcher.Close()
			})
		}
	}
	return func() (*stdtls.Certificate, error) {
		defer runtime.KeepAlive(gcFlag)
		updateMutex.RLock()
		defer updateMutex.RUnlock()
		return &cert, nil
	}, nil
}

// v3PacketPipe is an in-memory datagram pair: the Nowhere 3 protocol side sees a
// connected net.Conn while the tunnel side sees one C.UDPPacket per datagram.
// Its directions are opposite on the two views — a Write on the protocol side
// hands a user-to-target packet to the tunnel, and a Read takes a
// target-to-user packet the tunnel wrote back.
type v3PacketPipe struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}

	closeOnce sync.Once
}

func newV3PacketPipe() *v3PacketPipe {
	return &v3PacketPipe{
		in:     make(chan []byte, 64),
		out:    make(chan []byte, 64),
		closed: make(chan struct{}),
	}
}

// v3PacketConn is the datagram-oriented net.Conn facade the Nowhere 3 Portal and
// Egress upstreams use. One Read/Write moves exactly one packet.
type v3PacketConn struct {
	*v3PacketPipe
}

func (p *v3PacketPipe) netConn() net.Conn {
	return &v3PacketConn{v3PacketPipe: p}
}

func (c *v3PacketConn) Read(b []byte) (int, error) {
	select {
	case payload := <-c.out:
		return copy(b, payload), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *v3PacketConn) Write(b []byte) (int, error) {
	payload := make([]byte, len(b))
	copy(payload, b)
	select {
	case c.in <- payload:
		return len(b), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *v3PacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *v3PacketConn) LocalAddr() net.Addr  { return v3PipeAddr{} }
func (c *v3PacketConn) RemoteAddr() net.Addr { return v3PipeAddr{} }

func (c *v3PacketConn) SetDeadline(time.Time) error      { return nil }
func (c *v3PacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *v3PacketConn) SetWriteDeadline(time.Time) error { return nil }

type v3PipeAddr struct{}

func (v3PipeAddr) Network() string { return "nw3" }
func (v3PipeAddr) String() string  { return "nw3" }

// v3Packet adapts one Nowhere 3 datagram to C.UDPPacket. The flow is bound to a
// single target, so WriteBack passes addr through to the pipe, which ignores it.
type v3Packet struct {
	pc       *v3PacketPipe
	data     []byte
	metadata *C.Metadata
}

var _ C.UDPPacketInAddr = (*v3Packet)(nil)

func (p *v3Packet) Data() []byte {
	return p.data
}

func (p *v3Packet) WriteBack(b []byte, _ net.Addr) (int, error) {
	payload := make([]byte, len(b))
	copy(payload, b)
	select {
	case p.pc.out <- payload:
		return len(b), nil
	case <-p.pc.closed:
		return 0, net.ErrClosed
	}
}

func (p *v3Packet) Drop() {}

// LocalAddr returns the source IP/Port of the UDP packet. Nowhere 3 hands the
// host a target only, so the source stays unspecified.
func (p *v3Packet) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

// InAddr returns the address the packet arrived on.
func (p *v3Packet) InAddr() net.Addr {
	return &net.UDPAddr{}
}

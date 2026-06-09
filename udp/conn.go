package udp

import (
	"net/netip"

	"github.com/slackhq/nebula/config"
)

// MTU is the size of the UDP read/scratch buffers. It must hold the largest UDP
// datagram nebula sends or receives. For the classical handshake that is bounded
// by the jumbo data-plane MTU (9001), but the post-quantum pqIX handshake
// (qp-nebula) carries an ML-DSA-87 certificate (~4.6 KB signature) inside each
// message on top of the ML-KEM-1024 key material, so its largest flight (msg2)
// reaches ~11 KB - and a relay re-wraps that. 16384 holds it with headroom; too
// small a buffer silently truncates msg2 on receive and SendVia drops it on relay.
const MTU = 16384

type EncReader func(
	addr netip.AddrPort,
	payload []byte,
)

type Conn interface {
	Rebind() error
	LocalAddr() (netip.AddrPort, error)
	ListenOut(r EncReader) error
	WriteTo(b []byte, addr netip.AddrPort) error
	ReloadConfig(c *config.C)
	SupportsMultipleReaders() bool
	Close() error
}

type NoopConn struct{}

func (NoopConn) Rebind() error {
	return nil
}
func (NoopConn) LocalAddr() (netip.AddrPort, error) {
	return netip.AddrPort{}, nil
}
func (NoopConn) ListenOut(_ EncReader) error {
	return nil
}
func (NoopConn) SupportsMultipleReaders() bool {
	return false
}
func (NoopConn) WriteTo(_ []byte, _ netip.AddrPort) error {
	return nil
}
func (NoopConn) ReloadConfig(_ *config.C) {
	return
}
func (NoopConn) Close() error {
	return nil
}

//go:build linux && !e2e_testing
// +build linux,!e2e_testing

package udp

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestStdConnLargeDatagram round-trips datagrams the size of the post-quantum
// (pqIX) handshake flights through a real UDP socket. ML-KEM-1024 key material
// plus an ML-DSA-87 certificate (~4.6 KB signature) carried inside each message
// make these far larger than a classical handshake: msg1 ~7868 B and msg2
// ~11039 B - the latter exceeds the old 9001 buffer, which is exactly the bug this
// guards (a real socket truncates an over-buffer datagram; the in-memory e2e conn
// does not, so it masked it). Sizes are checked against MTU below so a future MTU
// reduction below a pqIX flight fails here loudly instead of silently in the field.
func TestStdConnLargeDatagram(t *testing.T) {
	l := slog.New(slog.NewTextHandler(io.Discard, nil))
	lo := netip.MustParseAddr("127.0.0.1")

	rx, err := NewListener(l, lo, 0, false, 1)
	require.NoError(t, err)
	rxAddr, err := rx.LocalAddr()
	require.NoError(t, err)

	tx, err := NewListener(l, lo, 0, false, 1)
	require.NoError(t, err)
	defer tx.Close()

	got := make(chan []byte, 4)
	go func() {
		_ = rx.ListenOut(func(_ netip.AddrPort, payload []byte) {
			cp := make([]byte, len(payload))
			copy(cp, payload)
			got <- cp
		})
	}()
	// Let the reader bind its callback before we send.
	time.Sleep(50 * time.Millisecond)

	// pqIX msg1 (~7868) and msg2 (~11039, the largest flight - over the old 9001
	// buffer), plus one byte under the full read buffer.
	for _, size := range []int{7868, 11039, MTU - 1} {
		want := make([]byte, size)
		for i := range want {
			want[i] = byte(i)
		}
		require.NoError(t, tx.WriteTo(want, rxAddr))

		select {
		case p := <-got:
			require.Equal(t, want, p, "a %d-byte datagram must arrive intact (not truncated to the read buffer)", size)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for the %d-byte datagram", size)
		}
	}
	rx.Close()
}

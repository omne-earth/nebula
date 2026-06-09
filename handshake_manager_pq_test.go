package nebula

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	metrics "github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/assert"
)

// TestHandshakeSubtypeForCurve pins the curve->subtype selection: only the
// ML-KEM-1024 node key uses the 3-message pqIX handshake; every classical curve
// uses Noise IX. The full pqIX runtime path (responder pending registration +
// completion) is exercised end to end by e2e.TestPQGoodHandshake.
func TestHandshakeSubtypeForCurve(t *testing.T) {
	assert.Equal(t, header.HandshakePQIX, handshakeSubtypeForCurve(cert.Curve_MLKEM1024))
	assert.Equal(t, header.HandshakeIXPSK0, handshakeSubtypeForCurve(cert.Curve_CURVE25519))
	assert.Equal(t, header.HandshakeIXPSK0, handshakeSubtypeForCurve(cert.Curve_P256))
}

// TestReapPendingResponders covers the pqIX responder reaper: an orphaned pending
// responder (msg3 never arrived) is deleted after its budget, while a completed
// responder and one still within budget are left alone. The reaper only touches
// the indexes map and its timer, so a minimal manager exercises it directly.
func TestReapPendingResponders(t *testing.T) {
	l := slog.New(slog.NewTextHandler(io.Discard, nil))
	mkHM := func() *HandshakeManager {
		return &HandshakeManager{
			vpnIps:                map[netip.Addr]*HandshakeHostInfo{},
			indexes:               map[uint32]*HandshakeHostInfo{},
			pendingResponderTimer: NewLockingTimerWheel[uint32](time.Millisecond, time.Second),
			metricTimedOut:        metrics.NewCounter(),
			l:                     l,
		}
	}
	start := time.Now()

	// An orphaned pending responder is reaped once its timeout elapses.
	hm := mkHM()
	hm.pendingResponderTimer.Advance(start) // initialize the wheel's clock
	hm.indexes[42] = &HandshakeHostInfo{hostinfo: &HostInfo{localIndexId: 42}, pendingResponder: true}
	hm.pendingResponderTimer.Add(42, time.Millisecond)
	hm.reapPendingResponders(start.Add(time.Second))
	assert.Nil(t, hm.queryIndex(42), "orphaned pending responder should be reaped")

	// A completed responder (ConnectionState set) is never reaped, even if its
	// timer fires while it briefly remains in the indexes map.
	hm = mkHM()
	hm.pendingResponderTimer.Advance(start)
	hm.indexes[13] = &HandshakeHostInfo{hostinfo: &HostInfo{localIndexId: 13, ConnectionState: &ConnectionState{}}, pendingResponder: true}
	hm.pendingResponderTimer.Add(13, time.Millisecond)
	hm.reapPendingResponders(start.Add(time.Second))
	assert.NotNil(t, hm.queryIndex(13), "a completed responder must not be reaped")

	// A firing timer for an index no longer tracked (already promoted to the main
	// host map) is a harmless no-op.
	hm = mkHM()
	hm.pendingResponderTimer.Advance(start)
	hm.pendingResponderTimer.Add(99, time.Millisecond)
	hm.reapPendingResponders(start.Add(time.Second))

	// A responder still within its budget survives.
	hm = mkHM()
	hm.pendingResponderTimer.Advance(start)
	hm.indexes[7] = &HandshakeHostInfo{hostinfo: &HostInfo{localIndexId: 7}, pendingResponder: true}
	hm.pendingResponderTimer.Add(7, time.Second)
	hm.reapPendingResponders(start.Add(time.Millisecond))
	assert.NotNil(t, hm.queryIndex(7), "responder within budget must survive")
}

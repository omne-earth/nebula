package nebula

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testReassembler() *chunkReassembler {
	return newChunkReassembler(test.NewLogger())
}

var testAddr = netip.MustParseAddrPort("[2001:db8::1]:4242")

// feed splits msg via the real splitter and returns the parsed (idx,count,frag)
// of each chunk so tests drive offer() with exactly what the wire would carry.
func splitForTest(t *testing.T, flightID uint32, msg []byte) []struct {
	idx, count uint8
	frag       []byte
} {
	chunks := handshakeChunks(flightID, msg)
	out := make([]struct {
		idx, count uint8
		frag       []byte
	}, len(chunks))
	for i, c := range chunks {
		h := &header.H{}
		require.NoError(t, h.Parse(c))
		require.Equal(t, header.HandshakeChunk, h.Type)
		require.Equal(t, flightID, h.RemoteIndex)
		idx, count := unpackChunkMeta(h.MessageCounter)
		out[i] = struct {
			idx, count uint8
			frag       []byte
		}{idx, count, c[header.Len:]}
		assert.LessOrEqual(t, len(c), HandshakeChunkWireMax, "chunk wire size must stay under the path ceiling")
	}
	return out
}

func TestChunkMetaRoundtrip(t *testing.T) {
	for _, tc := range []struct{ idx, count uint8 }{{0, 1}, {5, 6}, {0, 64}, {63, 64}, {200, 255}} {
		idx, count := unpackChunkMeta(packChunkMeta(tc.idx, tc.count))
		assert.Equal(t, tc.idx, idx)
		assert.Equal(t, tc.count, count)
	}
}

func TestChunkReassembleInOrder(t *testing.T) {
	cr := testReassembler()
	msg := make([]byte, maxHandshakeFragment*3+17) // 4 chunks
	for i := range msg {
		msg[i] = byte(i)
	}
	parts := splitForTest(t, 1, msg)
	require.Len(t, parts, 4)

	var got []byte
	var ok bool
	for _, p := range parts {
		got, ok = cr.offer(testAddr, 1, p.idx, p.count, p.frag)
	}
	require.True(t, ok)
	assert.Equal(t, msg, got)
}

func TestChunkReassembleReordered(t *testing.T) {
	cr := testReassembler()
	msg := make([]byte, maxHandshakeFragment*5)
	for i := range msg {
		msg[i] = byte(i * 7)
	}
	parts := splitForTest(t, 9, msg)
	order := []int{4, 0, 3, 1, 2}
	var got []byte
	var ok bool
	for _, j := range order {
		got, ok = cr.offer(testAddr, 9, parts[j].idx, parts[j].count, parts[j].frag)
	}
	require.True(t, ok)
	assert.Equal(t, msg, got)
}

func TestChunkDuplicateIsIdempotent(t *testing.T) {
	cr := testReassembler()
	msg := make([]byte, maxHandshakeFragment*2)
	parts := splitForTest(t, 2, msg)

	_, ok := cr.offer(testAddr, 2, parts[0].idx, parts[0].count, parts[0].frag)
	assert.False(t, ok)
	// resend chunk 0 — must not complete (chunk 1 still missing) and must not error
	_, ok = cr.offer(testAddr, 2, parts[0].idx, parts[0].count, parts[0].frag)
	assert.False(t, ok)
	got, ok := cr.offer(testAddr, 2, parts[1].idx, parts[1].count, parts[1].frag)
	require.True(t, ok)
	assert.Equal(t, msg, got)
}

func TestChunkConflictDropsFlight(t *testing.T) {
	cr := testReassembler()
	msg := make([]byte, maxHandshakeFragment*2)
	parts := splitForTest(t, 3, msg)

	_, ok := cr.offer(testAddr, 3, parts[0].idx, parts[0].count, parts[0].frag)
	assert.False(t, ok)
	// same slot, different bytes => poison => whole flight dropped
	poison := make([]byte, len(parts[0].frag))
	for i := range poison {
		poison[i] = 0xFF
	}
	_, ok = cr.offer(testAddr, 3, parts[0].idx, parts[0].count, poison)
	assert.False(t, ok)
	// the legit remaining chunk should NOT complete a flight (it was dropped);
	// it starts a fresh partial that needs chunk 0 again.
	_, ok = cr.offer(testAddr, 3, parts[1].idx, parts[1].count, parts[1].frag)
	assert.False(t, ok)
}

func TestChunkRejectsMalformed(t *testing.T) {
	cr := testReassembler()
	frag := make([]byte, 10)
	_, ok := cr.offer(testAddr, 1, 0, 0, frag) // count 0
	assert.False(t, ok)
	_, ok = cr.offer(testAddr, 1, 5, 5, frag) // idx == count
	assert.False(t, ok)
	_, ok = cr.offer(testAddr, 1, 0, maxChunksPerFlight+1, frag) // count too big
	assert.False(t, ok)
	_, ok = cr.offer(testAddr, 1, 0, 2, nil) // empty frag
	assert.False(t, ok)
	_, ok = cr.offer(testAddr, 1, 0, 2, make([]byte, maxHandshakeFragment+1)) // frag too big
	assert.False(t, ok)
}

func TestChunkTombstoneDropsLateChunks(t *testing.T) {
	cr := testReassembler()
	msg := make([]byte, maxHandshakeFragment*2)
	parts := splitForTest(t, 7, msg)
	cr.offer(testAddr, 7, parts[0].idx, parts[0].count, parts[0].frag)
	_, ok := cr.offer(testAddr, 7, parts[1].idx, parts[1].count, parts[1].frag)
	require.True(t, ok)
	// a late duplicate of any chunk must not re-complete (no second dispatch)
	_, ok = cr.offer(testAddr, 7, parts[0].idx, parts[0].count, parts[0].frag)
	assert.False(t, ok)
}

func TestChunkEvictionBound(t *testing.T) {
	cr := testReassembler()
	clock := time.Unix(0, 0)
	cr.now = func() time.Time { return clock }
	frag := make([]byte, 32)
	// Open more than maxChunkFlights partial flights (each count=2, never completed)
	for i := 0; i < maxChunkFlights+50; i++ {
		clock = clock.Add(time.Millisecond)
		addr := netip.AddrPortFrom(netip.MustParseAddr("2001:db8::2"), uint16(1024+i))
		cr.offer(addr, uint32(i), 0, 2, frag)
	}
	cr.mu.Lock()
	n := len(cr.flights)
	cr.mu.Unlock()
	assert.LessOrEqual(t, n, maxChunkFlights, "pending flights must stay bounded")
}

func TestChunkTTLSweep(t *testing.T) {
	cr := testReassembler()
	clock := time.Unix(100, 0)
	cr.now = func() time.Time { return clock }
	frag := make([]byte, 32)
	cr.offer(testAddr, 1, 0, 2, frag) // partial, never completes
	clock = clock.Add(chunkFlightTTL + time.Second)
	// admitting a new flight triggers the sweep, clearing the expired one
	other := netip.AddrPortFrom(netip.MustParseAddr("2001:db8::9"), 5000)
	cr.offer(other, 2, 0, 2, frag)
	cr.mu.Lock()
	_, stale := cr.flights[chunkFlightKey{addr: testAddr, flightID: 1}]
	cr.mu.Unlock()
	assert.False(t, stale, "expired partial flight must be swept")
}

func TestEmitHandshakeChunksRedundancyAndOrder(t *testing.T) {
	msg := make([]byte, maxHandshakeFragment*2+5) // 3 chunks
	for i := range msg {
		msg[i] = byte(i)
	}
	var sent [][]byte
	require.NoError(t, emitHandshakeChunks(42, msg, func(c []byte) error {
		sent = append(sent, append([]byte(nil), c...))
		return nil
	}))

	chunks := handshakeChunks(42, msg)
	n := len(chunks)
	require.Equal(t, 3, n)
	require.Equal(t, n*HandshakeChunkRedundancy, len(sent), "each chunk emitted HandshakeChunkRedundancy times")

	// Round-robin: copy r of chunk i lands at position r*n+i, and every emitted
	// datagram stays under the wire ceiling.
	for r := 0; r < HandshakeChunkRedundancy; r++ {
		for i := 0; i < n; i++ {
			assert.Equal(t, chunks[i], sent[r*n+i], "round-robin position")
		}
	}
	for _, c := range sent {
		assert.LessOrEqual(t, len(c), HandshakeChunkWireMax)
	}

	// One full round reassembles to the original.
	cr := testReassembler()
	var out []byte
	var ok bool
	for i := 0; i < n; i++ {
		h := &header.H{}
		require.NoError(t, h.Parse(sent[i]))
		idx, count := unpackChunkMeta(h.MessageCounter)
		out, ok = cr.offer(testAddr, h.RemoteIndex, idx, count, sent[i][header.Len:])
	}
	require.True(t, ok)
	assert.Equal(t, msg, out)
}

func TestEmitHandshakeChunksSmallStillChunks(t *testing.T) {
	msg := []byte("a small handshake flight well under the ceiling")
	var sent [][]byte
	require.NoError(t, emitHandshakeChunks(7, msg, func(c []byte) error {
		sent = append(sent, append([]byte(nil), c...))
		return nil
	}))
	// Always chunk: 1 logical chunk, emitted HandshakeChunkRedundancy times, each
	// a HandshakeChunk (never a whole/raw datagram).
	require.Equal(t, HandshakeChunkRedundancy, len(sent))
	for _, c := range sent {
		h := &header.H{}
		require.NoError(t, h.Parse(c))
		assert.Equal(t, header.HandshakeChunk, h.Type)
	}
	cr := testReassembler()
	h := &header.H{}
	require.NoError(t, h.Parse(sent[0]))
	idx, count := unpackChunkMeta(h.MessageCounter)
	out, ok := cr.offer(testAddr, h.RemoteIndex, idx, count, sent[0][header.Len:])
	require.True(t, ok)
	assert.Equal(t, msg, out)
}

func TestEmitHandshakeChunksRedundantCopiesCompleteOnce(t *testing.T) {
	// Feeding every emitted copy (all HandshakeChunkRedundancy rounds) into the
	// reassembler must complete the flight exactly once; later copies hit the
	// tombstone and return false.
	msg := make([]byte, maxHandshakeFragment*2)
	var sent [][]byte
	require.NoError(t, emitHandshakeChunks(11, msg, func(c []byte) error {
		sent = append(sent, append([]byte(nil), c...))
		return nil
	}))
	cr := testReassembler()
	completions := 0
	for _, c := range sent {
		h := &header.H{}
		require.NoError(t, h.Parse(c))
		idx, count := unpackChunkMeta(h.MessageCounter)
		if _, ok := cr.offer(testAddr, h.RemoteIndex, idx, count, c[header.Len:]); ok {
			completions++
		}
	}
	assert.Equal(t, 1, completions, "flight completes exactly once across all redundant copies")
}

func TestEmitHandshakeChunksPropagatesWriteError(t *testing.T) {
	msg := make([]byte, maxHandshakeFragment*2)
	sentinel := errors.New("chunk write failed")
	calls := 0
	err := emitHandshakeChunks(1, msg, func([]byte) error {
		calls++
		return sentinel
	})
	assert.Equal(t, sentinel, err)
	assert.Equal(t, 1, calls, "emit stops at the first write error")
}

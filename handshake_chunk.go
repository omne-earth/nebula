package nebula

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/slackhq/nebula/header"
)

// Handshake chunking. The pqIX ML-KEM flights (stage-1 ~7.9KB, msg2 ~6.4KB)
// exceed any single datagram a fragment-hostile path will carry: the kernel
// IP-fragments them and a non-fragmenting edge (GCP's v6 edge, consumer/mobile
// middleboxes) silently drops every fragment, so the handshake never completes.
//
// Instead of relying on IP fragmentation we split EVERY handshake datagram into
// application-level chunks, each small enough to cross any conformant path
// un-fragmented, and reassemble on the far side before feeding the reconstructed
// datagram to the normal handshake path. Every pqIX flight is chunked — even a sub-ceiling one goes out as a
// HandshakeChunk — so the kernel never sees a fragmentable pqIX datagram and the
// pqIX receive path is uniform (one code path, always exercised). Classical IX
// flights are small, never fragment, and stay on the whole-datagram path. Each chunk is sent HandshakeChunkRedundancy times for loss
// resilience without a retry-interval stall.
//
// Recovery is the existing handshake retry timer: lose a chunk, the flight
// times out and the whole flight is retransmitted (identical chunks, same
// flightID). No NACKs (a control message to an unauthenticated peer is a
// reflection vector). Reassembled bytes are never trusted as authenticated —
// noise ReadMessage remains the sole authority; reassembly only feeds it.

const (
	// HandshakeChunkWireMax is the largest nebula datagram (UDP payload) a chunk
	// may occupy on the wire. Chosen to sit under the IPv6 minimum-MTU floor
	// (1280) after IPv6 (40) + UDP (8) headers and a relay re-wrap, so a chunk
	// never IP-fragments on any conformant path.
	HandshakeChunkWireMax = 1152
	// maxHandshakeFragment is the bytes of the original handshake datagram
	// carried per chunk: the wire ceiling minus this chunk's own nebula header.
	maxHandshakeFragment = HandshakeChunkWireMax - header.Len // 1136

	// Reassembly bounds. Chunks arrive pre-authentication, so the buffer is
	// attacker-reachable and every dimension is capped.
	maxChunksPerFlight = 64 // a real flight is ~6 chunks; 64 covers growth
	maxFlightBytes     = maxChunksPerFlight * maxHandshakeFragment
	maxChunkFlights    = 128              // concurrent partial flights across all peers
	chunkFlightTTL     = 10 * time.Second // partial/tombstoned flight lifetime
)

// HandshakeChunkRedundancy is how many identical copies of each chunk the
// emitter sends. Handshakes are cold-path (~once per peer), so paying Nx the
// bytes once buys single-chunk burst-loss resilience without waiting a retry
// interval to discover the loss. The receiver de-dups idempotently, so this is
// purely an emit-side multiplier. Copies are sent round-robin (all chunks, then
// repeat) so the N copies of one chunk are spaced out, surviving short bursts.
const HandshakeChunkRedundancy = 3

// emitHandshakeChunks splits msg into wire chunks and writes each HandshakeChunkRedundancy
// times via write, round-robin. write is the per-datagram sink (direct UDP, or a
// relay SendVia). Always chunks — even a sub-ceiling flight goes out as one
// HandshakeChunk — so qp-nebula never hands the kernel a fragmentable handshake
// datagram and the receive path is uniform.
func emitHandshakeChunks(flightID uint32, msg []byte, write func([]byte) error) error {
	chunks := handshakeChunks(flightID, msg)
	for r := 0; r < HandshakeChunkRedundancy; r++ {
		for _, c := range chunks {
			if err := write(c); err != nil {
				return err
			}
		}
	}
	return nil
}

// packChunkMeta / unpack: count and idx ride in the header's MessageCounter
// (Encode forces Reserved to 0, so we cannot use it). flightID rides in
// RemoteIndex.
func packChunkMeta(idx, count uint8) uint64 { return uint64(count)<<8 | uint64(idx) }
func unpackChunkMeta(c uint64) (idx, count uint8) {
	return uint8(c & 0xff), uint8((c >> 8) & 0xff)
}

// handshakeChunks splits a handshake datagram into wire-ready chunk datagrams,
// one per <=maxHandshakeFragment slice. A flight at or below the fragment size
// yields a single chunk (always-chunk: even small flights ride the chunk path).
func handshakeChunks(flightID uint32, msg []byte) [][]byte {
	n := (len(msg) + maxHandshakeFragment - 1) / maxHandshakeFragment
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		start := i * maxHandshakeFragment
		end := start + maxHandshakeFragment
		if end > len(msg) {
			end = len(msg)
		}
		buf := make([]byte, header.Len+(end-start))
		header.Encode(buf, header.Version, header.HandshakeChunk, 0, flightID, packChunkMeta(uint8(i), uint8(n)))
		copy(buf[header.Len:], msg[start:end])
		out = append(out, buf)
	}
	return out
}

type chunkFlightKey struct {
	addr     netip.AddrPort
	flightID uint32
}

type chunkFlight struct {
	count    uint8
	got      uint8
	frags    [][]byte
	nbytes   int
	created  time.Time
	complete bool // tombstone: reassembled+dispatched, drop late/dup chunks
}

// chunkReassembler buffers partial handshake flights and emits the reconstructed
// datagram once every chunk of a flight has arrived. Safe for concurrent use.
type chunkReassembler struct {
	mu      sync.Mutex
	flights map[chunkFlightKey]*chunkFlight
	l       *slog.Logger
	now     func() time.Time // injectable for tests
}

func newChunkReassembler(l *slog.Logger) *chunkReassembler {
	return &chunkReassembler{
		flights: make(map[chunkFlightKey]*chunkFlight),
		l:       l,
		now:     time.Now,
	}
}

// offer ingests one chunk. It returns the reassembled original datagram and true
// once the final outstanding chunk of a flight arrives; otherwise nil, false.
// Malformed, conflicting, or over-budget input drops the whole flight (a clean
// retransmit rebuilds it) — it never partially trusts attacker-shaped state.
func (cr *chunkReassembler) offer(addr netip.AddrPort, flightID uint32, idx, count uint8, frag []byte) ([]byte, bool) {
	// Structural validation before taking the lock.
	if count == 0 || count > maxChunksPerFlight || idx >= count {
		return nil, false
	}
	if len(frag) == 0 || len(frag) > maxHandshakeFragment {
		return nil, false
	}

	key := chunkFlightKey{addr: addr, flightID: flightID}
	now := cr.now()

	cr.mu.Lock()
	defer cr.mu.Unlock()

	f := cr.flights[key]
	if f == nil {
		cr.sweepLocked(now)
		if len(cr.flights) >= maxChunkFlights {
			cr.evictOldestLocked()
		}
		f = &chunkFlight{count: count, frags: make([][]byte, count), created: now}
		cr.flights[key] = f
	}

	// Tombstone: this flight already reassembled and dispatched. Drop late dups
	// rather than dispatch a second time.
	if f.complete {
		return nil, false
	}

	// A differing chunk count for the same (addr,flightID) is a conflict — drop.
	if f.count != count {
		delete(cr.flights, key)
		cr.dropped(addr, flightID, "chunk count mismatch")
		return nil, false
	}

	if existing := f.frags[idx]; existing != nil {
		if bytes.Equal(existing, frag) {
			return nil, false // idempotent duplicate
		}
		// Same slot, different bytes: corruption or injection. Drop the flight.
		delete(cr.flights, key)
		cr.dropped(addr, flightID, "conflicting chunk (corruption or injection)")
		return nil, false
	}

	// Store a copy — frag aliases the listener's buffer.
	cp := make([]byte, len(frag))
	copy(cp, frag)
	f.frags[idx] = cp
	f.got++
	f.nbytes += len(cp)
	if f.nbytes > maxFlightBytes {
		delete(cr.flights, key)
		cr.dropped(addr, flightID, "flight exceeded byte budget")
		return nil, false
	}

	if f.got < f.count {
		return nil, false
	}

	// Complete: concatenate in order.
	out := make([]byte, 0, f.nbytes)
	for _, c := range f.frags {
		out = append(out, c...)
	}
	// Reassembled datagram must at least carry a nebula header to be dispatchable.
	if len(out) < header.Len {
		delete(cr.flights, key)
		return nil, false
	}
	// Tombstone the key; free the fragments.
	f.complete = true
	f.frags = nil
	f.nbytes = 0
	f.created = now
	return out, true
}

// dropped logs a discarded partial flight at debug. These are silent at info
// (a dropped flight just costs a retransmit), but a burst of them is the
// fingerprint of corruption or chunk injection — visible with QPN_LOG_LEVEL=debug.
func (cr *chunkReassembler) dropped(addr netip.AddrPort, flightID uint32, why string) {
	if cr.l.Enabled(context.Background(), slog.LevelDebug) {
		cr.l.Debug("Dropped handshake chunk flight", "from", addr, "flightID", flightID, "reason", why)
	}
}

// sweepLocked drops flights past their TTL. Bounded by maxChunkFlights so the
// linear scan is cheap; called only when admitting a new flight.
func (cr *chunkReassembler) sweepLocked(now time.Time) {
	for k, f := range cr.flights {
		if now.Sub(f.created) > chunkFlightTTL {
			delete(cr.flights, k)
		}
	}
}

// evictOldestLocked removes the oldest flight to make room under maxChunkFlights.
func (cr *chunkReassembler) evictOldestLocked() {
	var oldestKey chunkFlightKey
	var oldest time.Time
	first := true
	for k, f := range cr.flights {
		if first || f.created.Before(oldest) {
			oldestKey, oldest, first = k, f.created, false
		}
	}
	if !first {
		delete(cr.flights, oldestKey)
	}
}

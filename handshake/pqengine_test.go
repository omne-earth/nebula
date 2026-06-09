package handshake

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

func newPQStatic(t *testing.T) (pub, priv []byte) {
	t.Helper()
	pk, sk, err := mlkem1024.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ = pk.MarshalBinary()
	priv, _ = sk.MarshalBinary()
	return pub, priv
}

// TestPQEngineHandshake drives two pqEngines through the 3-message pqIX handshake and
// checks: payloads round-trip, both sides learn the peer static, and the transport keys
// agree (i2r/r2i) so the data plane interoperates.
func TestPQEngineHandshake(t *testing.T) {
	iPub, iPriv := newPQStatic(t)
	rPub, rPriv := newPQStatic(t)

	I, err := newPQEngine(true, iPub, iPriv)
	if err != nil {
		t.Fatal(err)
	}
	R, err := newPQEngine(false, rPub, rPriv)
	if err != nil {
		t.Fatal(err)
	}

	m1, _, _, err := I.WriteMessage(nil, []byte("p1"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _, err := R.ReadMessage(nil, m1); err != nil || !bytes.Equal(got, []byte("p1")) {
		t.Fatalf("msg1: %v %q", err, got)
	}

	m2, _, _, err := R.WriteMessage(nil, []byte("p2"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _, err := I.ReadMessage(nil, m2); err != nil || !bytes.Equal(got, []byte("p2")) {
		t.Fatalf("msg2: %v %q", err, got)
	}

	m3, iCS1, iCS2, err := I.WriteMessage(nil, []byte("p3"))
	if err != nil {
		t.Fatal(err)
	}
	if iCS1 == nil || iCS2 == nil {
		t.Fatal("initiator should derive transport keys on msg3")
	}
	got3, rCS1, rCS2, err := R.ReadMessage(nil, m3)
	if err != nil || !bytes.Equal(got3, []byte("p3")) {
		t.Fatalf("msg3: %v %q", err, got3)
	}
	if rCS1 == nil || rCS2 == nil {
		t.Fatal("responder should derive transport keys on msg3")
	}

	if I.MessageIndex() != 3 || R.MessageIndex() != 3 {
		t.Fatalf("message index: I=%d R=%d", I.MessageIndex(), R.MessageIndex())
	}
	if !bytes.Equal(I.PeerStatic(), rPub) {
		t.Fatal("initiator PeerStatic != responder static")
	}
	if !bytes.Equal(R.PeerStatic(), iPub) {
		t.Fatal("responder PeerStatic != initiator static")
	}

	// Transport agrees: cs1 = i2r, cs2 = r2i for both sides.
	nb := func() []byte { return make([]byte, 12) }
	ct, err := iCS1.EncryptDanger(nil, nil, []byte("i->r"), 0, nb())
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := rCS1.DecryptDanger(nil, nil, ct, 0, nb()); err != nil || !bytes.Equal(pt, []byte("i->r")) {
		t.Fatalf("i->r transport: %v %q", err, pt)
	}
	ct2, err := rCS2.EncryptDanger(nil, nil, []byte("r->i"), 0, nb())
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := iCS2.DecryptDanger(nil, nil, ct2, 0, nb()); err != nil || !bytes.Equal(pt, []byte("r->i")) {
		t.Fatalf("r->i transport: %v %q", err, pt)
	}
}

// TestPQEngineTamperFails: a flipped byte in the final message must fail the responder's
// decapsulation/AEAD.
func TestPQEngineTamperFails(t *testing.T) {
	iPub, iPriv := newPQStatic(t)
	rPub, rPriv := newPQStatic(t)
	I, _ := newPQEngine(true, iPub, iPriv)
	R, _ := newPQEngine(false, rPub, rPriv)

	m1, _, _, _ := I.WriteMessage(nil, []byte("p1"))
	R.ReadMessage(nil, m1)
	m2, _, _, _ := R.WriteMessage(nil, []byte("p2"))
	I.ReadMessage(nil, m2)
	m3, _, _, err := I.WriteMessage(nil, []byte("p3"))
	if err != nil {
		t.Fatal(err)
	}

	m3[len(m3)-1] ^= 0xff
	if _, _, _, err := R.ReadMessage(nil, m3); err == nil {
		t.Fatal("expected tampered msg3 to fail")
	}
}

// BenchmarkPQHandshake measures one full pqIX-analog handshake: engine setup
// (unmarshal static keys), the ephemeral keygen, two ML-KEM encapsulations and two
// decapsulations, the AES-GCM transcript, and Split - i.e. the per-handshake
// post-quantum crypto cost. Run with: go test ./handshake/ -bench PQHandshake -benchmem
func BenchmarkPQHandshake(b *testing.B) {
	sch := mlkem1024.Scheme()
	ipk, isk, _ := sch.GenerateKeyPair()
	rpk, rsk, _ := sch.GenerateKeyPair()
	iPub, _ := ipk.MarshalBinary()
	iPriv, _ := isk.MarshalBinary()
	rPub, _ := rpk.MarshalBinary()
	rPriv, _ := rsk.MarshalBinary()
	payload := []byte("x")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		I, _ := newPQEngine(true, iPub, iPriv)
		R, _ := newPQEngine(false, rPub, rPriv)
		m1, _, _, _ := I.WriteMessage(nil, payload)
		R.ReadMessage(nil, m1)
		m2, _, _, _ := R.WriteMessage(nil, payload)
		I.ReadMessage(nil, m2)
		m3, _, _, _ := I.WriteMessage(nil, payload)
		R.ReadMessage(nil, m3)
	}
}

// TestPQEngineReadRollback verifies a failed ReadMessage rolls back completely:
// step is not advanced and the transcript is restored, so a valid retransmit after
// a truncated/forged message still completes. Without the rollback a single bad
// packet would permanently wedge the handshake.
func TestPQEngineReadRollback(t *testing.T) {
	iPub, iPriv := newPQStatic(t)
	rPub, rPriv := newPQStatic(t)
	I, _ := newPQEngine(true, iPub, iPriv)
	R, _ := newPQEngine(false, rPub, rPriv)

	m1, _, _, _ := I.WriteMessage(nil, []byte("p1"))
	if _, _, _, err := R.ReadMessage(nil, m1); err != nil {
		t.Fatal(err)
	}
	m2, _, _, _ := R.WriteMessage(nil, []byte("p2"))

	// Truncate msg2 mid-flight: a valid ephemeral (so readE mixes the transcript)
	// followed by a missing KEM ciphertext. This must fail AND restore both step
	// and transcript.
	if _, _, _, err := I.ReadMessage(nil, m2[:1600]); err == nil {
		t.Fatal("expected a truncated msg2 to fail")
	}
	if I.MessageIndex() != 1 {
		t.Fatalf("a failed read must not advance step, got %d", I.MessageIndex())
	}

	// The real msg2 must process cleanly after the rolled-back failure.
	pt, _, _, err := I.ReadMessage(nil, m2)
	if err != nil || !bytes.Equal(pt, []byte("p2")) {
		t.Fatalf("valid msg2 after a rolled-back failure: %v %q", err, pt)
	}
	if I.MessageIndex() != 2 {
		t.Fatalf("a successful read should advance step to 2, got %d", I.MessageIndex())
	}
}

// TestPQEngineErrors exercises the engine's defensive branches: rejecting malformed static
// keys, truncated handshake messages (readE/readS/readKEM short), and out-of-sequence
// WriteMessage/ReadMessage calls.
func TestPQEngineErrors(t *testing.T) {
	pub, priv := newPQStatic(t)

	// Malformed static keys are rejected at construction.
	if _, err := newPQEngine(true, []byte{1, 2, 3}, priv); err == nil {
		t.Fatal("expected bad static public key to fail")
	}
	if _, err := newPQEngine(true, pub, []byte{1, 2, 3}); err == nil {
		t.Fatal("expected bad static private key to fail")
	}

	// A valid ML-KEM public key is one full ephemeral token; reusing it as a crafted
	// message lets readE succeed and the following token see an empty remainder.
	validEph, _ := newPQStatic(t)

	// readE short: msg1 shorter than one public key.
	R, _ := newPQEngine(false, pub, priv)
	if _, _, _, err := R.ReadMessage(nil, []byte{0, 1, 2, 3, 4}); err == nil {
		t.Fatal("expected short readE to fail")
	}

	// readS short: valid ephemeral, then no static bytes left.
	R2, _ := newPQEngine(false, pub, priv)
	if _, _, _, err := R2.ReadMessage(nil, validEph); err == nil {
		t.Fatal("expected short readS to fail")
	}

	// readKEM short: initiator at step 1, valid ephemeral then no ciphertext left.
	I, _ := newPQEngine(true, pub, priv)
	if _, _, _, err := I.WriteMessage(nil, []byte("p1")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := I.ReadMessage(nil, validEph); err == nil {
		t.Fatal("expected short readKEM to fail")
	}

	// Out-of-sequence: a responder never writes at step 0, an initiator never reads at step 0.
	Rw, _ := newPQEngine(false, pub, priv)
	if _, _, _, err := Rw.WriteMessage(nil, nil); err == nil {
		t.Fatal("expected responder WriteMessage at step 0 to fail")
	}
	Ir, _ := newPQEngine(true, pub, priv)
	if _, _, _, err := Ir.ReadMessage(nil, validEph); err == nil {
		t.Fatal("expected initiator ReadMessage at step 0 to fail")
	}
}

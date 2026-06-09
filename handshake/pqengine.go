package handshake

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/slackhq/nebula/noiseutil"
)

// pqEngine is the post-quantum handshakeEngine: a 3-message pqIX-analog over
// ML-KEM-1024 (qp-nebula). It mirrors the proven spike/pqnoise construction but is
// adapted for nebula's Machine: it takes EXTERNAL static keys (the node's ML-KEM cert
// keypair), carries an arbitrary payload in each message (the cert/index/time bytes the
// Machine marshals), and yields data-plane noiseutil.CipherState transport keys.
//
// The token sequence (E = ephemeral, S = static; ekem/skem = KEM encapsulation):
//
//	msg1  I -> R :  e, s,    [payload]     # statics cleartext, no key yet
//	msg2  R -> I :  e, ekem, skem, s, [payload]   # FS + auth I + enc(S_r)
//	msg3  I -> R :  skem, [payload]        # auth R ; then both Split()
//
// Design notes vs flynn/noise: a KEM cannot be a noise DHFunc (the ciphertext must be
// transmitted), so this is a hand-built Noise-analog. See .notes/docs/DESIGN.md.
// pqEngine satisfies the handshakeEngine interface the Machine drives.
var _ handshakeEngine = (*pqEngine)(nil)

type pqEngine struct {
	ss        *pqState
	sch       kem.Scheme
	initiator bool
	step      int

	sPub  kem.PublicKey // our static (the cert public key)
	sPriv kem.PrivateKey
	ePub  kem.PublicKey // our ephemeral (minted in writeE)
	ePriv kem.PrivateKey

	rePub    kem.PublicKey // peer ephemeral (learned in readE)
	rsPub    kem.PublicKey // peer static (learned in readS)
	rsPubRaw []byte        // ...its marshaled bytes, for PeerStatic()
}

// newPQEngine builds the post-quantum engine from the node's own static keypair
// (cert public key bytes + raw private key bytes).
func newPQEngine(initiator bool, staticPub, staticPriv []byte) (*pqEngine, error) {
	sch := mlkem1024.Scheme()
	pub, err := sch.UnmarshalBinaryPublicKey(staticPub)
	if err != nil {
		return nil, fmt.Errorf("pq static public key: %w", err)
	}
	priv, err := sch.UnmarshalBinaryPrivateKey(staticPriv)
	if err != nil {
		return nil, fmt.Errorf("pq static private key: %w", err)
	}
	return &pqEngine{
		ss:        newPQState(),
		sch:       sch,
		initiator: initiator,
		sPub:      pub,
		sPriv:     priv,
	}, nil
}

func (e *pqEngine) MessageIndex() int { return e.step }

func (e *pqEngine) PeerStatic() []byte { return e.rsPubRaw }

// transportKeys turns the chaining-key Split into the two data-plane cipher states,
// returned (i2r, r2i) - the same orientation flynn/noise uses, so the Machine maps them
// the same way.
func (e *pqEngine) transportKeys() (noiseutil.CipherState, noiseutil.CipherState, error) {
	k1, k2 := e.ss.split()
	cs1, err := noiseutil.NewCipherStateAESGCMFromKey(k1[:])
	if err != nil {
		return nil, nil, err
	}
	cs2, err := noiseutil.NewCipherStateAESGCMFromKey(k2[:])
	if err != nil {
		return nil, nil, err
	}
	return cs1, cs2, nil
}

// --- token helpers --------------------------------------------------------

func (e *pqEngine) writeE(out []byte) ([]byte, error) {
	pub, priv, err := e.sch.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	e.ePub, e.ePriv = pub, priv
	pb, err := pub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	e.ss.mixHash(pb)
	return append(out, pb...), nil
}

func (e *pqEngine) readE(in []byte) ([]byte, error) {
	n := e.sch.PublicKeySize()
	if len(in) < n {
		return nil, fmt.Errorf("pq readE: short message")
	}
	pub, err := e.sch.UnmarshalBinaryPublicKey(in[:n])
	if err != nil {
		return nil, err
	}
	e.rePub = pub
	e.ss.mixHash(in[:n])
	return in[n:], nil
}

func (e *pqEngine) writeS(out []byte) ([]byte, error) {
	pb, err := e.sPub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(out, e.ss.encryptAndHash(pb)...), nil
}

func (e *pqEngine) readS(in []byte) ([]byte, error) {
	n := e.sch.PublicKeySize()
	if e.ss.hasKey {
		n += gcmTagLen
	}
	if len(in) < n {
		return nil, fmt.Errorf("pq readS: short message")
	}
	pb, err := e.ss.decryptAndHash(in[:n])
	if err != nil {
		return nil, err
	}
	pub, err := e.sch.UnmarshalBinaryPublicKey(pb)
	if err != nil {
		return nil, err
	}
	e.rsPub = pub
	e.rsPubRaw = append([]byte(nil), pb...)
	return in[n:], nil
}

func (e *pqEngine) writeKEM(target kem.PublicKey, out []byte) ([]byte, error) {
	ct, ss, err := e.sch.Encapsulate(target)
	if err != nil {
		return nil, err
	}
	e.ss.mixHash(ct)
	e.ss.mixKey(ss)
	return append(out, ct...), nil
}

func (e *pqEngine) readKEM(priv kem.PrivateKey, in []byte) ([]byte, error) {
	n := e.sch.CiphertextSize()
	if len(in) < n {
		return nil, fmt.Errorf("pq readKEM: short message")
	}
	ss, err := e.sch.Decapsulate(priv, in[:n])
	if err != nil {
		return nil, err
	}
	e.ss.mixHash(in[:n])
	e.ss.mixKey(ss)
	return in[n:], nil
}

// --- driver ---------------------------------------------------------------

// WriteMessage produces this peer's next handshake flight carrying payload. On the
// final flight it returns the transport key pair (i2r, r2i).
func (e *pqEngine) WriteMessage(out, payload []byte) ([]byte, noiseutil.CipherState, noiseutil.CipherState, error) {
	var err error
	defer func() { e.step++ }()
	switch {
	case e.initiator && e.step == 0: // msg1: e, s, payload
		if out, err = e.writeE(out); err != nil {
			return nil, nil, nil, err
		}
		if out, err = e.writeS(out); err != nil {
			return nil, nil, nil, err
		}
		return append(out, e.ss.encryptAndHash(payload)...), nil, nil, nil

	case !e.initiator && e.step == 1: // msg2: e, ekem, skem, s, payload
		if out, err = e.writeE(out); err != nil {
			return nil, nil, nil, err
		}
		if out, err = e.writeKEM(e.rePub, out); err != nil {
			return nil, nil, nil, err
		}
		if out, err = e.writeKEM(e.rsPub, out); err != nil {
			return nil, nil, nil, err
		}
		if out, err = e.writeS(out); err != nil {
			return nil, nil, nil, err
		}
		return append(out, e.ss.encryptAndHash(payload)...), nil, nil, nil

	case e.initiator && e.step == 2: // msg3: skem, payload ; split
		if out, err = e.writeKEM(e.rsPub, out); err != nil {
			return nil, nil, nil, err
		}
		out = append(out, e.ss.encryptAndHash(payload)...)
		cs1, cs2, err := e.transportKeys()
		return out, cs1, cs2, err
	}
	return nil, nil, nil, fmt.Errorf("pq WriteMessage: unexpected step %d (initiator=%v)", e.step, e.initiator)
}

// ReadMessage consumes the peer's next flight, returning its payload. On the final
// flight it returns the transport key pair (i2r, r2i).
func (e *pqEngine) ReadMessage(out, message []byte) ([]byte, noiseutil.CipherState, noiseutil.CipherState, error) {
	// Checkpoint the symmetric state so a failed read (a truncated or forged
	// message) rolls back cleanly. The Machine treats a non-fatal ReadMessage
	// error as retryable, so the engine must not advance its step or leave the
	// transcript partially mixed - otherwise a later valid retransmit would be
	// processed at the wrong step (or against a corrupted transcript) and never
	// complete. Mirrors flynn/noise's checkpoint-and-rollback on read failure.
	saved := *e.ss
	out, cs1, cs2, err := e.readMessageStep(out, message)
	if err != nil {
		*e.ss = saved
		return nil, nil, nil, err
	}
	e.step++
	return out, cs1, cs2, nil
}

func (e *pqEngine) readMessageStep(out, message []byte) ([]byte, noiseutil.CipherState, noiseutil.CipherState, error) {
	var err error
	var rest []byte
	switch {
	case !e.initiator && e.step == 0: // read msg1: e, s, payload
		if rest, err = e.readE(message); err != nil {
			return nil, nil, nil, err
		}
		if rest, err = e.readS(rest); err != nil {
			return nil, nil, nil, err
		}
		pt, err := e.ss.decryptAndHash(rest)
		return append(out, pt...), nil, nil, err

	case e.initiator && e.step == 1: // read msg2: e, ekem, skem, s, payload
		if rest, err = e.readE(message); err != nil {
			return nil, nil, nil, err
		}
		if rest, err = e.readKEM(e.ePriv, rest); err != nil {
			return nil, nil, nil, err
		}
		if rest, err = e.readKEM(e.sPriv, rest); err != nil {
			return nil, nil, nil, err
		}
		if rest, err = e.readS(rest); err != nil {
			return nil, nil, nil, err
		}
		pt, err := e.ss.decryptAndHash(rest)
		return append(out, pt...), nil, nil, err

	case !e.initiator && e.step == 2: // read msg3: skem, payload ; split
		if rest, err = e.readKEM(e.sPriv, message); err != nil {
			return nil, nil, nil, err
		}
		pt, err := e.ss.decryptAndHash(rest)
		if err != nil {
			return nil, nil, nil, err
		}
		cs1, cs2, err := e.transportKeys()
		return append(out, pt...), cs1, cs2, err
	}
	return nil, nil, nil, fmt.Errorf("pq ReadMessage: unexpected step %d (initiator=%v)", e.step, e.initiator)
}

// --- symmetric state (hand-built Noise core) ------------------------------

const (
	pqProtocolName = "pqIXanalog_MLKEM1024_AESGCM_SHA256"
	gcmTagLen      = 16
)

// pqState mirrors Noise's SymmetricState: HKDF-SHA256 chaining, a SHA-256 transcript,
// and an AES-256-GCM AEAD keyed off the chain.
type pqState struct {
	ck     [32]byte
	h      [32]byte
	k      [32]byte
	hasKey bool
	n      uint64
}

func newPQState() *pqState {
	sum := sha256.Sum256([]byte(pqProtocolName))
	return &pqState{ck: sum, h: sum}
}

func (s *pqState) mixHash(data []byte) {
	hh := sha256.New()
	hh.Write(s.h[:])
	hh.Write(data)
	var out [32]byte
	hh.Sum(out[:0])
	s.h = out
}

func (s *pqState) mixKey(ikm []byte) {
	prk, err := hkdf.Extract(sha256.New, ikm, s.ck[:])
	if err != nil {
		panic(err)
	}
	out, err := hkdf.Expand(sha256.New, prk, "", 64)
	if err != nil {
		panic(err)
	}
	copy(s.ck[:], out[:32])
	copy(s.k[:], out[32:])
	s.hasKey = true
	s.n = 0
}

func (s *pqState) encryptAndHash(pt []byte) []byte {
	if !s.hasKey {
		s.mixHash(pt)
		return pt
	}
	cs, err := noiseutil.NewCipherStateAESGCMFromKey(s.k[:])
	if err != nil {
		panic(err)
	}
	ct, err := cs.EncryptDanger(nil, s.h[:], pt, s.n, make([]byte, 12))
	if err != nil {
		panic(err)
	}
	s.n++
	s.mixHash(ct)
	return ct
}

func (s *pqState) decryptAndHash(ct []byte) ([]byte, error) {
	if !s.hasKey {
		s.mixHash(ct)
		return ct, nil
	}
	cs, err := noiseutil.NewCipherStateAESGCMFromKey(s.k[:])
	if err != nil {
		return nil, err
	}
	aad := append([]byte(nil), s.h[:]...)
	pt, err := cs.DecryptDanger(nil, aad, ct, s.n, make([]byte, 12))
	if err != nil {
		return nil, err
	}
	s.n++
	s.mixHash(ct)
	return pt, nil
}

// split derives the two directional transport keys (i2r, r2i) from the final chaining
// key. Both peers run this on the same ck and derive the identical pair.
func (s *pqState) split() ([32]byte, [32]byte) {
	prk, err := hkdf.Extract(sha256.New, []byte{}, s.ck[:])
	if err != nil {
		panic(err)
	}
	out, err := hkdf.Expand(sha256.New, prk, "", 64)
	if err != nil {
		panic(err)
	}
	var k1, k2 [32]byte
	copy(k1[:], out[:32])
	copy(k2[:], out[32:])
	return k1, k2
}

package handshake

import (
	"fmt"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/noiseutil"
)

// buildEngine constructs the handshake engine for a credential: the post-quantum
// pqEngine for an ML-KEM-1024 cert (no noise pattern/cipher suite involved), otherwise
// the flynn/noise IX engine built from the credential's cipher suite.
func buildEngine(cred *Credential, initiator bool, info subtypeInfo) (handshakeEngine, error) {
	if cred.Cert.Curve() == cert.Curve_MLKEM1024 {
		return newPQEngine(initiator, cred.Cert.PublicKey(), cred.privateKey)
	}
	hs, err := cred.buildHandshakeState(initiator, info.pattern)
	if err != nil {
		return nil, fmt.Errorf("build noise state: %w", err)
	}
	return newNoiseEngine(hs, cred.cipherSuite), nil
}

// handshakeEngine is the Noise-shaped core that the Machine drives, abstracted so the
// Machine stays engine-agnostic. The classical Curve25519 / P256 IX path is a
// flynn/noise HandshakeState wrapped by noiseEngine; the post-quantum pqIX engine
// (ML-KEM-1024, qp-nebula) implements the same interface directly.
//
// The two noiseutil.CipherState returns are the transport key pair, non-nil only on
// the final handshake message (Noise's Split). They are the data-plane AEAD type, so
// no engine-specific cipher state leaks past the handshake boundary.
type handshakeEngine interface {
	// WriteMessage appends the next outgoing handshake message to out.
	WriteMessage(out, payload []byte) ([]byte, noiseutil.CipherState, noiseutil.CipherState, error)
	// ReadMessage consumes an incoming handshake message and returns its payload.
	ReadMessage(out, message []byte) ([]byte, noiseutil.CipherState, noiseutil.CipherState, error)
	// MessageIndex is the number of handshake messages sent + received so far.
	MessageIndex() int
	// PeerStatic returns the peer's static public key once it is known.
	PeerStatic() []byte
}

// noiseEngine adapts a flynn/noise HandshakeState to handshakeEngine, converting
// noise's *CipherState transport keys into the data-plane noiseutil.CipherState (the
// per-cipher AEAD) using the handshake's cipher.
type noiseEngine struct {
	hs     *noise.HandshakeState
	cipher noise.CipherFunc
}

func newNoiseEngine(hs *noise.HandshakeState, cipher noise.CipherFunc) *noiseEngine {
	return &noiseEngine{hs: hs, cipher: cipher}
}

func (e *noiseEngine) wrap(cs *noise.CipherState) noiseutil.CipherState {
	if cs == nil {
		return nil
	}
	return noiseutil.NewCipherState(cs, e.cipher)
}

func (e *noiseEngine) WriteMessage(out, payload []byte) ([]byte, noiseutil.CipherState, noiseutil.CipherState, error) {
	msg, cs1, cs2, err := e.hs.WriteMessage(out, payload)
	return msg, e.wrap(cs1), e.wrap(cs2), err
}

func (e *noiseEngine) ReadMessage(out, message []byte) ([]byte, noiseutil.CipherState, noiseutil.CipherState, error) {
	msg, cs1, cs2, err := e.hs.ReadMessage(out, message)
	return msg, e.wrap(cs1), e.wrap(cs2), err
}

func (e *noiseEngine) MessageIndex() int { return e.hs.MessageIndex() }

func (e *noiseEngine) PeerStatic() []byte { return e.hs.PeerStatic() }

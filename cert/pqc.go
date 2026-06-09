package cert

import (
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Raw key sizes (CIRCL encodings) for the post-quantum curves, used to validate
// PEM-decoded keys.
const (
	mlKEM1024PublicKeySize  = mlkem1024.PublicKeySize  // node static (handshake) key
	mlKEM1024PrivateKeySize = mlkem1024.PrivateKeySize
	mlDSA87PublicKeySize    = mldsa87.PublicKeySize // CA signing key
	mlDSA87PrivateKeySize   = mldsa87.PrivateKeySize
)

// Post-quantum curve identifiers, extending the generated Curve enum (qp-nebula).
//
// Unlike the classical curves, the post-quantum node and CA use DISTINCT
// algorithms: the node static (handshake) key is a KEM - ML-KEM-1024 (FIPS 203) -
// which cannot sign, so an ML-KEM-1024 node certificate is signed by an ML-DSA-87
// (FIPS 204) CA. A self-signed CA certificate carries the ML-DSA-87 key itself.
// This is the decoupling of "node key type" from "CA signature scheme" that the
// classical Curve enum bundles together (CURVE25519 -> Ed25519, P256 -> ECDSA).
//
// NB: Curve.String() is protobuf-generated off the enum descriptor, so it renders
// these as their numbers ("2"/"3"); the human names are wired where they are
// actually parsed (nebula-cert's -curve flag) in a later step.
const (
	Curve_MLKEM1024 Curve = 2 // node static key: ML-KEM-1024
	Curve_MLDSA87   Curve = 3 // CA signing key: ML-DSA-87
)

// isPQCurve reports whether c is one of the post-quantum curves.
func isPQCurve(c Curve) bool {
	return c == Curve_MLKEM1024 || c == Curve_MLDSA87
}

// signingCurveFor returns the curve of the key that must sign a certificate whose
// subject curve is c. Classical curves sign with themselves; both post-quantum
// curves are signed by ML-DSA-87 (the node KEM key cannot sign, and a CA self-signs
// with its own ML-DSA-87 key).
func signingCurveFor(c Curve) Curve {
	if isPQCurve(c) {
		return Curve_MLDSA87
	}
	return c
}

// pqSign produces an ML-DSA-87 signature over msg using the raw ML-DSA-87 private
// key bytes (CIRCL encoding). Pure ML-DSA-87, empty context - the same parameters
// verified wire-compatible with the suite OpenSSL in qp-nebula/spike/interop.
func pqSign(privKey, msg []byte) ([]byte, error) {
	sk, err := mldsa87.Scheme().UnmarshalBinaryPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-DSA-87 private key: %w", err)
	}
	return mldsa87.Scheme().Sign(sk, msg, nil), nil
}

// pqVerify checks an ML-DSA-87 signature over msg using the raw ML-DSA-87 public
// key bytes.
func pqVerify(pubKey, msg, sig []byte) bool {
	pk, err := mldsa87.Scheme().UnmarshalBinaryPublicKey(pubKey)
	if err != nil {
		return false
	}
	return mldsa87.Scheme().Verify(pk, msg, sig, nil)
}

// pqMLDSAPublicFromPrivate derives the ML-DSA-87 public key bytes from a raw private
// key - used to confirm a CA cert matches its signing key.
func pqMLDSAPublicFromPrivate(key []byte) ([]byte, error) {
	var sk mldsa87.PrivateKey
	if err := sk.UnmarshalBinary(key); err != nil {
		return nil, err
	}
	return sk.Public().(*mldsa87.PublicKey).MarshalBinary()
}

// pqMLKEMPublicFromPrivate derives the ML-KEM-1024 public key bytes from a raw private
// key - used to confirm a node cert matches its handshake key.
func pqMLKEMPublicFromPrivate(key []byte) ([]byte, error) {
	sk, err := mlkem1024.Scheme().UnmarshalBinaryPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return sk.Public().MarshalBinary()
}

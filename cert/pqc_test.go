package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net/netip"
	"testing"
	"time"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPQCertChain proves the post-quantum cert decoupling (qp-nebula): an ML-DSA-87
// CA mints and self-verifies, then signs an ML-KEM-1024 node certificate that
// verifies under the CA's ML-DSA-87 key. The node and CA use DISTINCT algorithms -
// the thing the classical Curve enum bundles. Wrong CA, a tampered signature, and an
// attempt to sign with the (non-signing) ML-KEM curve all fail.
func TestPQCertChain(t *testing.T) {
	before := time.Now().Add(-60 * time.Second).Round(time.Second)
	after := time.Now().Add(60 * time.Second).Round(time.Second)

	// --- ML-DSA-87 CA, self-signed ---
	caPub, caPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caPubB, err := caPub.MarshalBinary()
	require.NoError(t, err)
	caPrivB, err := caPriv.MarshalBinary()
	require.NoError(t, err)

	caTBS := TBSCertificate{
		Version:   Version2,
		Name:      "pq ca",
		IsCA:      true,
		NotBefore: before,
		NotAfter:  after,
		Curve:     Curve_MLDSA87,
		PublicKey: caPubB,
	}
	ca, err := caTBS.Sign(nil, Curve_MLDSA87, caPrivB)
	require.NoError(t, err)
	assert.Equal(t, Curve_MLDSA87, ca.Curve())
	assert.True(t, ca.CheckSignature(caPubB), "CA self-signature must verify")

	// --- ML-KEM-1024 node, signed by the ML-DSA-87 CA ---
	nodePub, _, err := mlkem1024.Scheme().GenerateKeyPair()
	require.NoError(t, err)
	nodePubB, err := nodePub.MarshalBinary()
	require.NoError(t, err)

	nodeTBS := TBSCertificate{
		Version:   Version2,
		Name:      "node-1.mesh",
		Networks:  []netip.Prefix{mustParsePrefixUnmapped("10.42.0.1/16")},
		Groups:    []string{"operators"},
		NotBefore: before,
		NotAfter:  after,
		Curve:     Curve_MLKEM1024,
		PublicKey: nodePubB,
	}
	node, err := nodeTBS.Sign(ca, Curve_MLDSA87, caPrivB)
	require.NoError(t, err)
	assert.Equal(t, Curve_MLKEM1024, node.Curve())
	assert.Len(t, node.PublicKey(), 1568, "node carries the ML-KEM-1024 key (1568B)")
	assert.True(t, node.CheckSignature(caPubB), "node cert must verify under the CA key")

	// --- negatives ---
	otherPub, _, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherB, err := otherPub.MarshalBinary()
	require.NoError(t, err)
	assert.False(t, node.CheckSignature(otherB), "must NOT verify under a different CA")

	// The ML-KEM curve is a KEM and cannot sign - signing with it must be rejected.
	_, err = nodeTBS.Sign(ca, Curve_MLKEM1024, nodePubB)
	assert.Error(t, err, "signing with an ML-KEM curve must be rejected")
}

// TestPQCurveHelpers covers signingCurveFor / isPQCurve for every curve (including
// the classical branches) and the enum string registration.
func TestPQCurveHelpers(t *testing.T) {
	assert.Equal(t, Curve_CURVE25519, signingCurveFor(Curve_CURVE25519))
	assert.Equal(t, Curve_P256, signingCurveFor(Curve_P256))
	assert.Equal(t, Curve_MLDSA87, signingCurveFor(Curve_MLKEM1024))
	assert.Equal(t, Curve_MLDSA87, signingCurveFor(Curve_MLDSA87))

	assert.True(t, isPQCurve(Curve_MLKEM1024))
	assert.True(t, isPQCurve(Curve_MLDSA87))
	assert.False(t, isPQCurve(Curve_CURVE25519))
	assert.False(t, isPQCurve(Curve_P256))
}

// TestPQSignVerifyErrors covers the error/false paths of pqSign and pqVerify.
func TestPQSignVerifyErrors(t *testing.T) {
	caPub, caPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caPubB, err := caPub.MarshalBinary()
	require.NoError(t, err)
	caPrivB, err := caPriv.MarshalBinary()
	require.NoError(t, err)

	msg := []byte("message")

	_, err = pqSign([]byte("too short"), msg)
	assert.Error(t, err, "invalid private key bytes must error")

	sig, err := pqSign(caPrivB, msg)
	require.NoError(t, err)
	assert.True(t, pqVerify(caPubB, msg, sig))

	assert.False(t, pqVerify([]byte("too short"), msg, sig), "invalid public key bytes -> false")
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xff
	assert.False(t, pqVerify(caPubB, msg, bad), "tampered signature -> false")
	assert.False(t, pqVerify(caPubB, []byte("other"), sig), "wrong message -> false")
}

// TestPQSignCurveMismatch covers the relaxed signingCurveFor() check: a valid
// classical signing curve is still rejected for an ML-KEM node cert.
func TestPQSignCurveMismatch(t *testing.T) {
	before := time.Now().Add(-60 * time.Second).Round(time.Second)
	after := time.Now().Add(60 * time.Second).Round(time.Second)

	caPub, caPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caPubB, err := caPub.MarshalBinary()
	require.NoError(t, err)
	caPrivB, err := caPriv.MarshalBinary()
	require.NoError(t, err)
	ca, err := (&TBSCertificate{
		Version: Version2, Name: "ca", IsCA: true, NotBefore: before, NotAfter: after,
		Curve: Curve_MLDSA87, PublicKey: caPubB,
	}).Sign(nil, Curve_MLDSA87, caPrivB)
	require.NoError(t, err)

	nodePub, _, err := mlkem1024.Scheme().GenerateKeyPair()
	require.NoError(t, err)
	nodePubB, err := nodePub.MarshalBinary()
	require.NoError(t, err)
	nodeTBS := TBSCertificate{
		Version: Version2, Name: "n", Networks: []netip.Prefix{mustParsePrefixUnmapped("10.0.0.1/24")},
		NotBefore: before, NotAfter: after, Curve: Curve_MLKEM1024, PublicKey: nodePubB,
	}

	// CURVE25519 is a valid signing curve but wrong for an ML-KEM node cert.
	_, err = nodeTBS.Sign(ca, Curve_CURVE25519, make([]byte, ed25519.PrivateKeySize))
	assert.Error(t, err, "classical signer for a PQ node cert must be rejected")
}

// TestPQPEMKeys covers the post-quantum PEM key marshaling: the ML-KEM-1024 node
// key-agreement key and the ML-DSA-87 CA signing key round-trip, and wrong-length
// inputs are rejected.
func TestPQPEMKeys(t *testing.T) {
	// --- ML-KEM-1024 node key (key-agreement path) ---
	nodePub, nodePriv, err := mlkem1024.Scheme().GenerateKeyPair()
	require.NoError(t, err)
	nPubB, err := nodePub.MarshalBinary()
	require.NoError(t, err)
	nPrivB, err := nodePriv.MarshalBinary()
	require.NoError(t, err)

	gotPub, _, curve, err := UnmarshalPublicKeyFromPEM(MarshalPublicKeyToPEM(Curve_MLKEM1024, nPubB))
	require.NoError(t, err)
	assert.Equal(t, Curve_MLKEM1024, curve)
	assert.Equal(t, nPubB, gotPub)

	gotPriv, _, curve, err := UnmarshalPrivateKeyFromPEM(MarshalPrivateKeyToPEM(Curve_MLKEM1024, nPrivB))
	require.NoError(t, err)
	assert.Equal(t, Curve_MLKEM1024, curve)
	assert.Equal(t, nPrivB, gotPriv)

	// --- ML-DSA-87 CA key (signing path) ---
	caPub, caPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cPubB, err := caPub.MarshalBinary()
	require.NoError(t, err)
	cPrivB, err := caPriv.MarshalBinary()
	require.NoError(t, err)

	gotCaPub, _, curve, err := UnmarshalPublicKeyFromPEM(MarshalSigningPublicKeyToPEM(Curve_MLDSA87, cPubB))
	require.NoError(t, err)
	assert.Equal(t, Curve_MLDSA87, curve)
	assert.Equal(t, cPubB, gotCaPub)

	gotCaPriv, _, curve, err := UnmarshalSigningPrivateKeyFromPEM(MarshalSigningPrivateKeyToPEM(Curve_MLDSA87, cPrivB))
	require.NoError(t, err)
	assert.Equal(t, Curve_MLDSA87, curve)
	assert.Equal(t, cPrivB, gotCaPriv)

	// --- wrong-length inputs are rejected ---
	_, _, _, err = UnmarshalPublicKeyFromPEM(pem.EncodeToMemory(&pem.Block{Type: MLKEM1024PublicKeyBanner, Bytes: []byte("short")}))
	assert.Error(t, err)
	_, _, _, err = UnmarshalPrivateKeyFromPEM(pem.EncodeToMemory(&pem.Block{Type: MLKEM1024PrivateKeyBanner, Bytes: []byte("short")}))
	assert.Error(t, err)
	_, _, _, err = UnmarshalSigningPrivateKeyFromPEM(pem.EncodeToMemory(&pem.Block{Type: MLDSA87PrivateKeyBanner, Bytes: []byte("short")}))
	assert.Error(t, err)
}

// TestPQDerivePublic covers deriving the public key from a private key for both PQ
// algorithms (used to confirm a cert matches its key), plus the error paths.
func TestPQDerivePublic(t *testing.T) {
	caPub, caPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caPubB, _ := caPub.MarshalBinary()
	caPrivB, _ := caPriv.MarshalBinary()
	got, err := pqMLDSAPublicFromPrivate(caPrivB)
	require.NoError(t, err)
	assert.Equal(t, caPubB, got)
	_, err = pqMLDSAPublicFromPrivate([]byte("short"))
	assert.Error(t, err)

	nPub, nPriv, err := mlkem1024.Scheme().GenerateKeyPair()
	require.NoError(t, err)
	nPubB, _ := nPub.MarshalBinary()
	nPrivB, _ := nPriv.MarshalBinary()
	gotN, err := pqMLKEMPublicFromPrivate(nPrivB)
	require.NoError(t, err)
	assert.Equal(t, nPubB, gotN)
	_, err = pqMLKEMPublicFromPrivate([]byte("short"))
	assert.Error(t, err)
}

// TestPQVerifyPrivateKey covers certificateV2.VerifyPrivateKey for both PQ kinds:
// the ML-DSA-87 CA path and the ML-KEM-1024 node path, success and mismatch.
func TestPQVerifyPrivateKey(t *testing.T) {
	before := time.Now().Add(-time.Minute).Round(time.Second)
	after := time.Now().Add(time.Hour).Round(time.Second)

	caPub, caPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caPubB, _ := caPub.MarshalBinary()
	caPrivB, _ := caPriv.MarshalBinary()
	ca, err := (&TBSCertificate{
		Version: Version2, Name: "ca", IsCA: true, NotBefore: before, NotAfter: after,
		Curve: Curve_MLDSA87, PublicKey: caPubB,
	}).Sign(nil, Curve_MLDSA87, caPrivB)
	require.NoError(t, err)

	require.NoError(t, ca.VerifyPrivateKey(Curve_MLDSA87, caPrivB))
	_, otherPriv, _ := mldsa87.GenerateKey(rand.Reader)
	otherPrivB, _ := otherPriv.MarshalBinary()
	assert.Error(t, ca.VerifyPrivateKey(Curve_MLDSA87, otherPrivB), "wrong CA key")
	assert.Error(t, ca.VerifyPrivateKey(Curve_MLDSA87, []byte("short")), "invalid CA key bytes")

	nPub, nPriv, err := mlkem1024.Scheme().GenerateKeyPair()
	require.NoError(t, err)
	nPubB, _ := nPub.MarshalBinary()
	nPrivB, _ := nPriv.MarshalBinary()
	node, err := (&TBSCertificate{
		Version: Version2, Name: "n", Networks: []netip.Prefix{mustParsePrefixUnmapped("10.0.0.1/24")},
		NotBefore: before, NotAfter: after, Curve: Curve_MLKEM1024, PublicKey: nPubB,
	}).Sign(ca, Curve_MLDSA87, caPrivB)
	require.NoError(t, err)

	require.NoError(t, node.VerifyPrivateKey(Curve_MLKEM1024, nPrivB))
	_, otherNPriv, _ := mlkem1024.Scheme().GenerateKeyPair()
	otherNPrivB, _ := otherNPriv.MarshalBinary()
	assert.Error(t, node.VerifyPrivateKey(Curve_MLKEM1024, otherNPrivB), "wrong node key")
	assert.Error(t, node.VerifyPrivateKey(Curve_MLKEM1024, []byte("short")), "invalid node key bytes")
}

// TestPQEncryptedSigningKey covers the encrypted ML-DSA-87 CA key path (the -encrypt
// flag): encrypt/marshal then decrypt/unmarshal round-trips, and a wrong-length key
// is rejected.
func TestPQEncryptedSigningKey(t *testing.T) {
	_, caPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caPrivB, _ := caPriv.MarshalBinary()
	pass := []byte("hunter2")
	params := NewArgon2Parameters(2*1024, 2, 1)

	enc, err := EncryptAndMarshalSigningPrivateKey(Curve_MLDSA87, caPrivB, pass, params)
	require.NoError(t, err)
	curve, dec, _, err := DecryptAndUnmarshalSigningPrivateKey(pass, enc)
	require.NoError(t, err)
	assert.Equal(t, Curve_MLDSA87, curve)
	assert.Equal(t, caPrivB, dec)

	// A blob that decrypts to the wrong length must be rejected.
	encBad, err := EncryptAndMarshalSigningPrivateKey(Curve_MLDSA87, []byte("short"), pass, NewArgon2Parameters(2*1024, 2, 1))
	require.NoError(t, err)
	_, _, _, err = DecryptAndUnmarshalSigningPrivateKey(pass, encBad)
	assert.Error(t, err)
}

// TestPQCAPoolVerify covers CAPool.verify's relaxed curve check: an ML-KEM-1024 node
// cert must verify under its ML-DSA-87 CA (the signer curve != cert curve case).
func TestPQCAPoolVerify(t *testing.T) {
	before := time.Now().Add(-time.Minute).Round(time.Second)
	after := time.Now().Add(time.Hour).Round(time.Second)

	caPub, caPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caPubB, _ := caPub.MarshalBinary()
	caPrivB, _ := caPriv.MarshalBinary()
	ca, err := (&TBSCertificate{
		Version: Version2, Name: "ca", IsCA: true, NotBefore: before, NotAfter: after,
		Curve: Curve_MLDSA87, PublicKey: caPubB,
	}).Sign(nil, Curve_MLDSA87, caPrivB)
	require.NoError(t, err)

	nPub, _, err := mlkem1024.Scheme().GenerateKeyPair()
	require.NoError(t, err)
	nPubB, _ := nPub.MarshalBinary()
	node, err := (&TBSCertificate{
		Version: Version2, Name: "n", Networks: []netip.Prefix{mustParsePrefixUnmapped("10.0.0.1/24")},
		NotBefore: before, NotAfter: after, Curve: Curve_MLKEM1024, PublicKey: nPubB,
	}).Sign(ca, Curve_MLDSA87, caPrivB)
	require.NoError(t, err)

	pool := NewCAPool()
	require.NoError(t, pool.AddCA(ca))
	_, err = pool.VerifyCertificate(time.Now(), node)
	require.NoError(t, err, "ML-KEM-1024 node must verify under its ML-DSA-87 CA")
}

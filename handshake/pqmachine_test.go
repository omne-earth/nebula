package handshake

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/require"
)

// newPQCertState builds a test peer with an ML-KEM-1024 node cert signed by an ML-DSA-87
// CA. The Credential's cipher suite is nil - the post-quantum path uses the pqEngine, not
// a noise cipher suite.
func newPQCertState(t *testing.T, ca cert.Certificate, caKey []byte, name string, networks []netip.Prefix) *testCertState {
	t.Helper()
	c, _, rawPriv, _ := ct.NewTestCert(
		cert.Version2, cert.Curve_MLKEM1024, ca, caKey,
		name, ca.NotBefore(), ca.NotAfter(), networks, nil, nil,
	)
	priv, _, _, err := cert.UnmarshalPrivateKeyFromPEM(rawPriv)
	require.NoError(t, err)
	hsBytes, err := c.MarshalForHandshakes()
	require.NoError(t, err)
	return &testCertState{
		version: cert.Version2,
		creds: map[cert.Version]*Credential{
			cert.Version2: NewCredential(c, hsBytes, priv, nil),
		},
	}
}

// TestMachinePQHandshake drives two Machines through a full 3-message pqIX handshake:
// NewMachine dispatches to the pqEngine for the ML-KEM-1024 credentials, the certs are
// exchanged + verified under the ML-DSA-87 CA, and the resulting transport keys
// interoperate. The initiator completes by WRITING msg3, the responder by READING it.
func TestMachinePQHandshake(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(cert.Version2, cert.Curve_MLDSA87, time.Time{}, time.Time{}, nil, nil, nil)
	caPool := ct.NewTestCAPool(ca)
	v := testVerifier(caPool)

	initCS := newPQCertState(t, ca, caKey, "pq-init", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respCS := newPQCertState(t, ca, caKey, "pq-resp", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	initM, err := NewMachine(cert.Version2, initCS.getCredential, v,
		func() (uint32, error) { return 1000, nil }, true, header.HandshakePQIX)
	require.NoError(t, err)
	respM, err := NewMachine(cert.Version2, respCS.getCredential, v,
		func() (uint32, error) { return 2000, nil }, false, header.HandshakePQIX)
	require.NoError(t, err)

	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)

	msg2, r1, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)
	require.Nil(t, r1, "responder not complete after msg1")
	require.NotEmpty(t, msg2)

	msg3, initResult, err := initM.ProcessPacket(nil, msg2)
	require.NoError(t, err)
	require.NotNil(t, initResult, "initiator completes by writing msg3")
	require.NotEmpty(t, msg3)

	_, respResult, err := respM.ProcessPacket(nil, msg3)
	require.NoError(t, err)
	require.NotNil(t, respResult, "responder completes by reading msg3")

	// Transport keys interoperate: initiator encrypts on EKey, responder decrypts on DKey.
	nb := func() []byte { return make([]byte, 12) }
	c1, err := initResult.EKey.EncryptDanger(nil, nil, []byte("ping"), 0, nb())
	require.NoError(t, err)
	p1, err := respResult.DKey.DecryptDanger(nil, nil, c1, 0, nb())
	require.NoError(t, err)
	require.Equal(t, []byte("ping"), p1)

	c2, err := respResult.EKey.EncryptDanger(nil, nil, []byte("pong"), 0, nb())
	require.NoError(t, err)
	p2, err := initResult.DKey.DecryptDanger(nil, nil, c2, 0, nb())
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), p2)

	// Each side verified the other's cert under the CA.
	require.Equal(t, "pq-resp", initResult.RemoteCert.Certificate.Name())
	require.Equal(t, "pq-init", respResult.RemoteCert.Certificate.Name())
}

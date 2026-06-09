package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPQCertCLI drives qp-nebula-cert end to end for the post-quantum curves: an
// ML-DSA-87 CA is created, an ML-KEM-1024 node keypair is generated, the node is
// signed by the CA, and the resulting chain verifies - the node cert (ML-KEM-1024)
// under the CA's ML-DSA-87 key.
func TestPQCertCLI(t *testing.T) {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	ob, eb := &bytes.Buffer{}, &bytes.Buffer{}
	nopw := &StubPasswordReader{}

	caKey, caCrt := p("ca.key"), p("ca.crt")
	require.NoError(t, ca([]string{
		"-version", "2", "-name", "pq ca", "-curve", "MLDSA87",
		"-out-key", caKey, "-out-crt", caCrt, "-duration", "24h",
	}, ob, eb, nopw), eb.String())

	nodeKey, nodePub := p("node.key"), p("node.pub")
	require.NoError(t, keygen([]string{
		"-curve", "MLKEM1024", "-out-key", nodeKey, "-out-pub", nodePub,
	}, ob, eb), eb.String())

	nodeCrt := p("node.crt")
	require.NoError(t, signCert([]string{
		"-version", "2", "-ca-key", caKey, "-ca-crt", caCrt,
		"-name", "node1", "-networks", "10.42.0.1/16",
		"-in-pub", nodePub, "-out-crt", nodeCrt, "-duration", "1h",
	}, ob, eb, nopw), eb.String())

	// The CA cert is a self-signed ML-DSA-87 cert.
	caPEM, err := os.ReadFile(caCrt)
	require.NoError(t, err)
	caCert, _, err := cert.UnmarshalCertificateFromPEM(caPEM)
	require.NoError(t, err)
	assert.Equal(t, cert.Curve_MLDSA87, caCert.Curve())
	assert.True(t, caCert.IsCA())
	assert.True(t, caCert.CheckSignature(caCert.PublicKey()), "CA self-signature")

	// The node cert carries an ML-KEM-1024 key and verifies under the CA.
	nodePEM, err := os.ReadFile(nodeCrt)
	require.NoError(t, err)
	nodeCert, _, err := cert.UnmarshalCertificateFromPEM(nodePEM)
	require.NoError(t, err)
	assert.Equal(t, cert.Curve_MLKEM1024, nodeCert.Curve())
	assert.Len(t, nodeCert.PublicKey(), 1568)
	assert.True(t, nodeCert.CheckSignature(caCert.PublicKey()), "node cert must verify under the CA")

	// Sign again, letting `sign` generate the node key itself (exercises the
	// newKeypair ML-KEM-1024 path and writing the node private key as PEM).
	node2Key, node2Crt := p("node2.key"), p("node2.crt")
	require.NoError(t, signCert([]string{
		"-version", "2", "-ca-key", caKey, "-ca-crt", caCrt,
		"-name", "node2", "-networks", "10.42.0.2/16",
		"-out-key", node2Key, "-out-crt", node2Crt, "-duration", "1h",
	}, ob, eb, nopw), eb.String())

	n2k, err := os.ReadFile(node2Key)
	require.NoError(t, err)
	_, _, n2curve, err := cert.UnmarshalPrivateKeyFromPEM(n2k)
	require.NoError(t, err)
	assert.Equal(t, cert.Curve_MLKEM1024, n2curve, "sign generated an ML-KEM-1024 node key")

	// print and verify must handle the PQ cert (closes the Phase-2a tail).
	require.NoError(t, printCert([]string{"-path", nodeCrt}, ob, eb), eb.String())
	require.NoError(t, printCert([]string{"-path", nodeCrt, "-json"}, ob, eb), eb.String())
	require.NoError(t, verify([]string{"-ca", caCrt, "-crt", nodeCrt}, ob, eb), eb.String())
}

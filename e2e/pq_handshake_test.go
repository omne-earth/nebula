//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// TestPQGoodHandshake brings up two post-quantum nodes - ML-KEM-1024 node certs
// signed by an ML-DSA-87 CA - and drives a full 3-message pqIX handshake to a
// working tunnel, end to end through the real connection manager. This is the
// node-to-node analog of TestGoodHandshake for the post-quantum curve.
func TestPQGoodHandshake(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_MLDSA87, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "me  ", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "them", "10.128.0.2/24", nil)

	// Put their address in my lighthouse so I know where to reach them; the
	// responder learns my address from the incoming handshake.
	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	theirControl.Start()

	t.Log("Trigger a pqIX handshake from me to them")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me")))

	// Route every packet - msg1, msg2, msg3, then the cached data packet - until
	// the data lands on their tun. This drives the full 3-message handshake
	// through both connection managers.
	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)

	t.Log("pqIX tunnel established; assert bidirectional traffic")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}

// TestPQRelays is the pqIX analog of TestRelays: me reaches them only through a
// relay node, so the relay forwards the post-quantum handshake. This stresses the
// relay-forwarding path with the much larger ML-KEM-1024 flights (msg2 ~6.4 KB),
// which the relay re-wraps in its own tunnel.
func TestPQRelays(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_MLDSA87, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "me     ", "10.128.0.1/24", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "relay  ", "10.128.0.128/24", m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "them   ", "10.128.0.2/24", m{"relay": m{"use_relays": true}})

	myControl.InjectLightHouseAddr(relayVpnIpNet[0].Addr(), relayUdpAddr)
	myControl.InjectRelays(theirVpnIpNet[0].Addr(), []netip.Addr{relayVpnIpNet[0].Addr()})
	relayControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	t.Log("Trigger a pqIX handshake from me to them via the relay")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me")))

	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
}

// TestPQUntrustedCARejected verifies the runtime rejects a post-quantum peer whose
// cert is signed by an untrusted CA: the responder must not reply to msg1 or leave
// any pending state behind (the cert is verified while processing msg1, before any
// index is allocated).
func TestPQUntrustedCARejected(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_MLDSA87, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	ca2, _, caKey2, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_MLDSA87, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	// me trusts ca; them is signed by ca2, which me (and them) do not trust each other under.
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "me  ", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca2, caKey2, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	theirControl.Start()

	t.Log("Initiate from me; deliver msg1 to the untrusting responder")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi")))
	msg1 := getCompleteHandshake(t, myControl)
	theirControl.InjectUDPPacket(msg1)

	t.Log("The responder must drop it: no msg2, no tunnel, no pending responder")
	time.Sleep(100 * time.Millisecond)
	assert.Nil(t, theirControl.GetFromUDP(false), "responder must not reply to an untrusted-CA initiator")
	assert.Empty(t, theirControl.ListHostmapHosts(false), "no tunnel for an untrusted cert")
	assert.Empty(t, theirControl.ListHostmapHosts(true), "no pending responder for an untrusted cert")

	myControl.Stop()
	theirControl.Stop()
}

// TestPQHandshakeTruncatedMsg2Recovery verifies a truncated pqIX msg2 is ignored
// without killing the initiator's pending handshake, and the real msg2 still
// completes the tunnel.
func TestPQHandshakeTruncatedMsg2Recovery(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_MLDSA87, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "me  ", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	theirControl.Start()

	t.Log("Trigger handshake, deliver msg1, get the responder's msg2")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi")))
	msg1 := getCompleteHandshake(t, myControl)
	theirControl.InjectUDPPacket(msg1)
	msg2 := getCompleteHandshake(t, theirControl)

	t.Log("Inject a truncated msg2; the initiator must ignore it and keep its pending handshake")
	trunc := msg2.Copy()
	trunc.Data = trunc.Data[:header.Len]
	myControl.InjectUDPPacket(trunc)
	assert.NotEmpty(t, myControl.ListHostmapHosts(true), "pending handshake must survive a truncated msg2")

	t.Log("Inject the real msg2 and route to completion")
	myControl.InjectUDPPacket(msg2)
	cached := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi"), cached, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}

// TestPQRehandshaking is the pqIX analog of TestRehandshaking: it stands up a
// post-quantum tunnel, renews one side's ML-KEM-1024 cert (adding a group), and
// verifies the rehandshake runs the full pqIX exchange again, the peer learns the
// new cert, and the tunnel collapses to a single one carrying the new identity.
func TestPQRehandshaking(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_MLDSA87, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, myConfig := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "me  ", "10.128.0.2/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, theirConfig := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "them", "10.128.0.1/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	theirControl.Start()

	t.Log("Stand up a pqIX tunnel")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	t.Log("Renew my ML-KEM cert with a new group and reload")
	_, _, myNextPrivKey, myNextPEM := cert_test.NewTestCert(cert.Version2, cert.Curve_MLKEM1024, ca, caKey, "me", time.Now(), time.Now().Add(5*time.Minute), myVpnIpNet, nil, []string{"new group"})
	caB, err := ca.MarshalPEM()
	require.NoError(t, err)
	myConfig.Settings["pki"] = m{
		"ca":   string(caB),
		"cert": string(myNextPEM),
		"key":  string(myNextPrivKey),
	}
	rc, err := yaml.Marshal(myConfig.Settings)
	require.NoError(t, err)
	myConfig.ReloadConfigString(string(rc))

	t.Log("Spin until they rehandshake and see my new cert")
	for {
		assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
		c := theirControl.GetHostInfoByVpnAddr(myVpnIpNet[0].Addr(), false)
		if c != nil && len(c.Cert.Groups()) != 0 {
			break
		}
		time.Sleep(time.Second)
	}

	t.Log("Flip their firewall to require the new group, catching a tunnel that reverts")
	rc, err = yaml.Marshal(theirConfig.Settings)
	require.NoError(t, err)
	var theirNewConfig m
	require.NoError(t, yaml.Unmarshal(rc, &theirNewConfig))
	theirNewConfig["firewall"].(map[string]any)["inbound"] = []m{{
		"proto": "any",
		"port":  "any",
		"group": "new group",
	}}
	rc, err = yaml.Marshal(theirNewConfig)
	require.NoError(t, err)
	theirConfig.ReloadConfigString(string(rc))

	t.Log("Spin until a single tunnel remains")
	for len(myControl.GetHostmap().Indexes)+len(theirControl.GetHostmap().Indexes) > 2 {
		assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
		time.Sleep(time.Second)
	}
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	c := theirControl.GetHostInfoByVpnAddr(myVpnIpNet[0].Addr(), false)
	assert.Contains(t, c.Cert.Groups(), "new group", "the renewed pqIX cert must win")
	assert.Len(t, myControl.ListHostmapHosts(false), 1)
	assert.Len(t, theirControl.ListHostmapHosts(false), 1)
	assert.Len(t, myControl.ListHostmapIndexes(false), 1)
	assert.Len(t, theirControl.ListHostmapIndexes(false), 1)

	myControl.Stop()
	theirControl.Stop()
}

// TestPQStage1Race is the pqIX analog of TestStage1Race: two post-quantum nodes
// handshake each other simultaneously. Each ends up both an initiator and a
// responder, so two tunnels form; traffic must flow and the connection manager
// must then collapse down to a single tunnel per side. This exercises the pqIX
// responder path racing the initiator path on the same node.
func TestPQStage1Race(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_MLDSA87, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "me  ", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	theirControl.Start()

	t.Log("Trigger a pqIX handshake on both sides at once")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me")))
	theirControl.InjectTunPacket(BuildTunUDPPacket(myVpnIpNet[0].Addr(), 80, theirVpnIpNet[0].Addr(), 80, []byte("Hi from them")))

	t.Log("Cross-inject both msg1 packets")
	myHsForThem := getCompleteHandshake(t, myControl)
	theirHsForMe := getCompleteHandshake(t, theirControl)
	r.InjectUDPPacket(theirControl, myControl, theirHsForMe)
	r.InjectUDPPacket(myControl, theirControl, myHsForThem)

	t.Log("Route until each side's cached packet is delivered")
	myCachedPacket := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)
	theirCachedPacket := r.RouteForAllUntilTxTun(myControl)
	assertUdpPacket(t, []byte("Hi from them"), theirCachedPacket, theirVpnIpNet[0].Addr(), myVpnIpNet[0].Addr(), 80, 80)

	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	t.Log("Two tunnels (initiator + responder) on each side initially")
	assert.Len(t, myControl.ListHostmapHosts(false), 1)
	assert.Len(t, theirControl.ListHostmapHosts(false), 1)
	assert.Len(t, myControl.ListHostmapIndexes(false), 2)
	assert.Len(t, theirControl.ListHostmapIndexes(false), 2)

	t.Log("Spin until the connection manager collapses to a single tunnel")
	for len(myControl.GetHostmap().Indexes)+len(theirControl.GetHostmap().Indexes) > 2 {
		assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
		t.Log("Connection manager hasn't ticked yet")
		time.Sleep(time.Second)
	}

	assert.Len(t, myControl.ListHostmapHosts(false), 1)
	assert.Len(t, theirControl.ListHostmapHosts(false), 1)
	assert.Len(t, myControl.ListHostmapIndexes(false), 1)
	assert.Len(t, theirControl.ListHostmapIndexes(false), 1)

	myControl.Stop()
	theirControl.Stop()
}

// TestPQHandshakeRetransmitDuplicate is the pqIX analog of
// TestHandshakeRetransmitDuplicate: a retransmitted (identical) msg1 must resend
// the responder's cached msg2 rather than build a second responder. We assert the
// responder keeps exactly one pending entry across the duplicate and that the
// tunnel completes to a single hostinfo on each side.
func TestPQHandshakeRetransmitDuplicate(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_MLDSA87, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "me  ", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	theirControl.Start()

	t.Log("Trigger a pqIX handshake and grab msg1")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi")))
	msg1 := getCompleteHandshake(t, myControl)

	t.Log("Deliver msg1; the responder registers one pending handshake and sends msg2")
	theirControl.InjectUDPPacket(msg1)
	_ = getCompleteHandshake(t, theirControl)
	assert.Len(t, theirControl.ListHostmapIndexes(true), 1, "one pending responder after msg1")

	t.Log("Deliver the SAME msg1 again; dedup must resend the cached msg2, not add a responder")
	theirControl.InjectUDPPacket(msg1)
	resp2 := getCompleteHandshake(t, theirControl)
	assert.NotNil(t, resp2, "duplicate msg1 should get the cached msg2")
	assert.Len(t, theirControl.ListHostmapIndexes(true), 1, "still exactly one pending responder after the duplicate")

	t.Log("Complete the handshake (initiator emits msg3 + the cached data packet); route it through")
	myControl.InjectUDPPacket(resp2)
	cached := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi"), cached, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)

	t.Log("Verify exactly one tunnel per side and traffic flows")
	assert.Len(t, myControl.ListHostmapHosts(false), 1)
	assert.Len(t, theirControl.ListHostmapHosts(false), 1)
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}

// TestPQDataBeforeMsg3 reproduces the tunnel-destruction race seen on real
// fleets: the pqIX initiator completes on SENDING msg3 and immediately flushes
// its cached data packet, but msg3 is a multi-fragment ~8KB datagram while the
// data is one small packet, so on a real network the data can arrive FIRST.
// The responder is still mid-handshake for that index; it must drop the early
// packet, NOT send a recv_error - a recv_error makes the initiator close the
// healthy tunnel it just completed, the responder's probes then draw the mirror
// recv_error, and every subsequent handshake dies the same way (the mesh never
// converges). Asserts the handshake survives the reorder and the SAME tunnel
// (one index per side, no re-handshake) carries traffic.
func TestPQDataBeforeMsg3(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_MLDSA87, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "me  ", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	theirControl.Start()

	t.Log("Trigger a pqIX handshake from me to them")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me")))

	t.Log("Walk msg1 and msg2 by hand")
	msg1 := getCompleteHandshake(t, myControl)
	r.InjectUDPPacket(myControl, theirControl, msg1)
	msg2 := getCompleteHandshake(t, theirControl)
	r.InjectUDPPacket(theirControl, myControl, msg2)

	t.Log("I complete on sending msg3 and flush the cached data right behind it")
	// Classify each reassembled flight by header: the initiator retransmits msg1
	// on its tryInterval until msg2 is processed, so blind pops can grab a
	// retransmit and mislabel the packets. getCompleteHandshake reassembles each
	// chunked flight so msg3 (multi-chunk) is reconstructed whole, exactly as the
	// receiver would see it after reassembly.
	var msg3, data *udp.Packet
	for msg3 == nil || data == nil {
		p := getCompleteHandshake(t, myControl)
		h := &header.H{}
		require.NoError(t, h.Parse(p.Data))
		switch {
		case h.Type == header.Handshake && h.MessageCounter == 3:
			msg3 = p
		case h.Type == header.Message:
			data = p
		default:
			// msg1 retransmit - irrelevant to the race
		}
	}

	t.Log("Deliver the small data packet FIRST - on the wire it beats the fragmented msg3")
	r.InjectUDPPacket(myControl, theirControl, data)
	r.InjectUDPPacket(myControl, theirControl, msg3)

	// The early data is DROPPED (not queued), so wait for the responder to finish
	// processing msg3 before asserting traffic - assertTunnel sends a single ping
	// and a ping that races the completion would be dropped the same way.
	deadline := time.Now().Add(5 * time.Second)
	for len(theirControl.ListHostmapIndexes(false)) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	require.Len(t, theirControl.ListHostmapIndexes(false), 1, "responder must complete after msg3")

	t.Log("The early data is dropped, the handshake still completes, the tunnel carries traffic")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	t.Log("Exactly one tunnel per side - no recv_error teardown, no re-handshake")
	assert.Len(t, myControl.ListHostmapIndexes(false), 1)
	assert.Len(t, theirControl.ListHostmapIndexes(false), 1)

	myControl.Stop()
	theirControl.Stop()
}

// TestPQHandshakeSurvivesFragmentHostileEdge reproduces the real-fleet failure
// where a node's pqIX handshake never crosses a fragment-hostile edge. The pqIX
// stage-1 flight (~7.9KB) and msg2 (~6.4KB) exceed any single datagram a
// fragment-dropping path (GCP's v6 edge, consumer/mobile middleboxes) will
// carry, so the whole handshake is silently dropped and the tunnel never forms.
//
// The router drops every datagram larger than fragHostileMax (the actual
// fragmentation boundary on a 1280-MTU v6 path). Today's code emits the flights
// whole -> they are dropped -> the handshake never completes (the test fails on
// the deadline). With handshake chunking, every emitted datagram fits, survives
// the edge, reassembles on the far side, and the tunnel forms.
func TestPQHandshakeSurvivesFragmentHostileEdge(t *testing.T) {
	t.Parallel()

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_MLDSA87, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "me  ", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	// The fragment-hostile edge: anything that wouldn't fit the 1280 floor is
	// dropped, exactly as a non-fragmenting middlebox would.
	r.SetDropFilter(func(p *udp.Packet) bool { return len(p.Data) > fragHostileMax })

	myControl.Start()
	theirControl.Start()

	t.Log("Trigger a pqIX handshake across an edge that drops fragmentable datagrams")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me")))

	// Fail fast: today the oversized flights are dropped by the edge and routing
	// never returns; the deadline fires with a clear message instead of hanging to
	// the suite -timeout. Post-chunking every datagram fits and this completes fast.
	done := deadline(t, 15)

	// Route until the cached data lands on their tun.
	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)

	t.Log("Tunnel formed through the edge; assert bidirectional traffic")
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
	done()

	myControl.Stop()
	theirControl.Stop()
}

// getCompleteHandshake drains one outbound handshake flight from c and returns it
// as a single datagram. Every handshake flight is chunked AND each chunk is sent
// HandshakeChunkRedundancy times, so the wire carries count*redundancy datagrams
// per flight, emitted contiguously. We drain exactly that many (de-duping by idx)
// so the redundant copies don't pollute the next read, then reassemble. A flight
// that somehow arrives whole (non-chunk) is returned unchanged.
func getCompleteHandshake(t *testing.T, c *nebula.Control) *udp.Packet {
	t.Helper()
	p := c.GetFromUDP(true)
	h := &header.H{}
	require.NoError(t, h.Parse(p.Data))
	if h.Type != header.HandshakeChunk {
		return p
	}
	flightID := h.RemoteIndex
	count := uint8((h.MessageCounter >> 8) & 0xff)
	require.Greater(t, count, uint8(0))
	frags := make([][]byte, count)
	store := func(hh *header.H, pkt *udp.Packet) {
		i := uint8(hh.MessageCounter & 0xff)
		require.Less(t, i, count)
		if frags[i] == nil {
			frags[i] = append([]byte(nil), pkt.Data[header.Len:]...)
		}
	}
	store(h, p)
	total := int(count) * nebula.HandshakeChunkRedundancy
	for read := 1; read < total; read++ {
		np := c.GetFromUDP(true)
		nh := &header.H{}
		require.NoError(t, nh.Parse(np.Data))
		require.Equal(t, header.HandshakeChunk, nh.Type, "interleaved non-chunk while draining a flight")
		require.Equal(t, flightID, nh.RemoteIndex, "interleaved chunk from a different flight")
		store(nh, np)
	}
	var data []byte
	for i, f := range frags {
		require.NotNil(t, f, "missing chunk %d after draining all copies", i)
		data = append(data, f...)
	}
	return &udp.Packet{To: p.To, From: p.From, Data: data}
}

// drainRawFlight reads one outbound flight from c and returns its UNIQUE chunk
// datagrams (one copy of each idx), UNreassembled. The wire carries
// count*redundancy datagrams; we drain them all and return the count distinct
// chunks for tests that drive the ingest path by hand. A whole (non-chunk)
// datagram is returned as-is.
func drainRawFlight(t *testing.T, c *nebula.Control) []*udp.Packet {
	t.Helper()
	p := c.GetFromUDP(true)
	h := &header.H{}
	require.NoError(t, h.Parse(p.Data))
	if h.Type != header.HandshakeChunk {
		return []*udp.Packet{p}
	}
	count := int((h.MessageCounter >> 8) & 0xff)
	uniq := make([]*udp.Packet, count)
	seen := func(hh *header.H, pkt *udp.Packet) {
		i := int(hh.MessageCounter & 0xff)
		require.Less(t, i, count)
		if uniq[i] == nil {
			uniq[i] = pkt
		}
	}
	seen(h, p)
	total := count * nebula.HandshakeChunkRedundancy
	for read := 1; read < total; read++ {
		np := c.GetFromUDP(true)
		nh := &header.H{}
		require.NoError(t, nh.Parse(np.Data))
		require.Equal(t, header.HandshakeChunk, nh.Type)
		seen(nh, np)
	}
	for i, u := range uniq {
		require.NotNil(t, u, "missing chunk %d", i)
	}
	return uniq
}

// TestPQHandshakeChunkIngest exercises outside.go's HandshakeChunk routing
// directly, without a router: a partial flight must be buffered (no dispatch, no
// reply, no recv_error), and only the final chunk — delivered out of order —
// completes reassembly and lets the handshake proceed. This isolates the ingest
// half of chunking from the end-to-end edge test.
func TestPQHandshakeChunkIngest(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_MLDSA87, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "me  ", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	theirControl.Start()

	t.Log("Trigger a handshake and capture msg1 as its raw on-wire chunks")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi")))
	chunks := drainRawFlight(t, myControl)
	require.Greater(t, len(chunks), 1, "msg1 must be chunked for this test to mean anything")
	for _, c := range chunks {
		h := &header.H{}
		require.NoError(t, h.Parse(c.Data))
		require.Equal(t, header.HandshakeChunk, h.Type)
	}

	t.Log("Deliver every chunk but one (in reverse order): the responder must buffer, not act")
	for i := len(chunks) - 1; i >= 1; i-- {
		theirControl.InjectUDPPacket(chunks[i])
	}
	time.Sleep(100 * time.Millisecond)
	assert.Nil(t, theirControl.GetFromUDP(false), "no reply while the flight is incomplete")
	// The pqIX responder lives in the index map until msg3 completes it (see
	// TestPQHandshakeRetransmitDuplicate); a partial flight registers nothing.
	assert.Empty(t, theirControl.ListHostmapIndexes(true), "no pending responder from a partial flight")

	t.Log("Deliver the missing first chunk: reassembly completes and the responder emits msg2")
	theirControl.InjectUDPPacket(chunks[0])
	msg2 := getCompleteHandshake(t, theirControl)
	require.NotNil(t, msg2)
	assert.Len(t, theirControl.ListHostmapIndexes(true), 1, "exactly one pending responder after the flight completes")

	t.Log("Finish the handshake end to end to prove the reassembled msg1 was genuinely usable")
	myControl.InjectUDPPacket(msg2)
	cached := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi"), cached, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}

// fragHostileMax is the largest UDP payload that still fits the IPv6 minimum-MTU
// floor (1280) after the IPv6 (40) + UDP (8) headers, i.e. 1232. A datagram
// larger than this would IP-fragment on a 1280-MTU path; a fragment-hostile
// middlebox drops it. Our chunk ceiling (HandshakeChunkWireMax = 1152) sits below
// this with room for a relay re-wrap, which is exactly why it was chosen.
const fragHostileMax = 1232

// TestPQHandshakeNeverFragments asserts the invariant directly: across a full
// pqIX handshake, qp-nebula never emits a whole Handshake datagram (everything is
// chunked) and no HandshakeChunk exceeds the wire ceiling. This is the always-
// chunk guarantee — the kernel is never handed a fragmentable handshake datagram.
func TestPQHandshakeNeverFragments(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_MLDSA87, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "me  ", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	r.SetTap(func(p *udp.Packet) {
		h := &header.H{}
		if h.Parse(p.Data) != nil {
			return
		}
		assert.NotEqual(t, header.Handshake, h.Type, "handshake must always be chunked, never emitted whole")
		if h.Type == header.HandshakeChunk {
			assert.LessOrEqual(t, len(p.Data), nebula.HandshakeChunkWireMax, "chunk exceeds the wire ceiling")
		}
	})

	myControl.Start()
	theirControl.Start()

	t.Log("Run a full handshake; the tap asserts every datagram is chunked and within the ceiling")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me")))
	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
}

// TestPQRelaySurvivesFragmentHostileEdge is TestPQRelays across a fragment-hostile
// path: me reaches them only through a relay, and every hop drops fragmentable
// datagrams. The relayed handshake completes only because the relay path is also
// chunked — a whole relayed flight (~8KB inner, relay-wrapped) would be dropped.
// This is the mobile case: CGNAT forces relays, and mobile middleboxes drop
// fragments.
func TestPQRelaySurvivesFragmentHostileEdge(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_MLDSA87, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "me     ", "10.128.0.1/24", m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "relay  ", "10.128.0.128/24", m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServerWithCurve(cert.Curve_MLKEM1024, cert.Version2, ca, caKey, "them   ", "10.128.0.2/24", m{"relay": m{"use_relays": true}})

	myControl.InjectLightHouseAddr(relayVpnIpNet[0].Addr(), relayUdpAddr)
	myControl.InjectRelays(theirVpnIpNet[0].Addr(), []netip.Addr{relayVpnIpNet[0].Addr()})
	relayControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	// Every hop is fragment-hostile, including the relay re-wrap.
	r.SetDropFilter(func(p *udp.Packet) bool { return len(p.Data) > fragHostileMax })

	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	done := deadline(t, 15)
	t.Log("Relayed pqIX handshake across a fragment-hostile path")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me")))
	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)
	done()

	myControl.Stop()
	relayControl.Stop()
	theirControl.Stop()
}

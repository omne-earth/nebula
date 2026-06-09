package handshake

import (
	"fmt"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/header"
)

// msgFlags tracks what application data a handshake message carries.
type msgFlags struct {
	expectsPayload bool // message carries indexes and time
	expectsCert    bool // message carries the certificate
}

// subtypeInfo bundles the noise pattern with the per-message flags for a
// given handshake subtype.
type subtypeInfo struct {
	pattern noise.HandshakePattern
	msgs    []msgFlags
}

// subtypeInfos defines the noise pattern and message content layout for each
// handshake subtype.
var subtypeInfos = map[header.MessageSubType]subtypeInfo{
	// IX: 2 messages, both carry payload and cert
	header.HandshakeIXPSK0: {
		pattern: noise.HandshakeIX,
		msgs: []msgFlags{
			{expectsPayload: true, expectsCert: true},
			{expectsPayload: true, expectsCert: true},
		},
	},

	// pqIX: 3 messages over ML-KEM-1024 (qp-nebula). msg1 and msg2 carry payload + cert
	// (statics and certs are exchanged in-band); msg3 completes - the initiator already
	// sent its cert in msg1, and both indexes are exchanged by msg2. There is no noise
	// pattern: the engine is selected by the credential's ML-KEM curve, not a DH pattern.
	header.HandshakePQIX: {
		msgs: []msgFlags{
			{expectsPayload: true, expectsCert: true},
			{expectsPayload: true, expectsCert: true},
			{expectsPayload: false, expectsCert: false},
		},
	},
}

func subtypeInfoFor(subtype header.MessageSubType) (subtypeInfo, error) {
	if info, ok := subtypeInfos[subtype]; ok {
		return info, nil
	}
	return subtypeInfo{}, fmt.Errorf("%w: %d", ErrUnknownSubtype, subtype)
}

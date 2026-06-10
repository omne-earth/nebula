package header

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type headerTest struct {
	expectedBytes []byte
	*H
}

// 0001 0010 00010010
var headerBigEndianTests = []headerTest{{
	expectedBytes: []byte{0x54, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9},
	// 1010 0000
	H: &H{
		// 1111 1+2+4+8 = 15
		Version:        5,
		Type:           4,
		Subtype:        0,
		Reserved:       0,
		RemoteIndex:    10,
		MessageCounter: 9,
	},
},
}

func TestEncode(t *testing.T) {
	for _, tt := range headerBigEndianTests {
		b, err := tt.Encode(make([]byte, Len))
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, tt.expectedBytes, b)
	}
}

func TestParse(t *testing.T) {
	for _, tt := range headerBigEndianTests {
		b := tt.expectedBytes
		parsedHeader := &H{}
		parsedHeader.Parse(b)

		if !reflect.DeepEqual(tt.H, parsedHeader) {
			t.Fatalf("got %#v; want %#v", parsedHeader, tt.H)
		}
	}
}

func TestTypeName(t *testing.T) {
	assert.Equal(t, "test", TypeName(Test))
	assert.Equal(t, "test", (&H{Type: Test}).TypeName())

	assert.Equal(t, "unknown", TypeName(99))
	assert.Equal(t, "unknown", (&H{Type: 99}).TypeName())
}

func TestSubTypeName(t *testing.T) {
	assert.Equal(t, "testRequest", SubTypeName(Test, TestRequest))
	assert.Equal(t, "testRequest", (&H{Type: Test, Subtype: TestRequest}).SubTypeName())

	assert.Equal(t, "unknown", SubTypeName(99, TestRequest))
	assert.Equal(t, "unknown", (&H{Type: 99, Subtype: TestRequest}).SubTypeName())

	assert.Equal(t, "unknown", SubTypeName(Test, 99))
	assert.Equal(t, "unknown", (&H{Type: Test, Subtype: 99}).SubTypeName())

	assert.Equal(t, "none", SubTypeName(Message, 0))
	assert.Equal(t, "none", (&H{Type: Message, Subtype: 0}).SubTypeName())
}

func TestTypeMap(t *testing.T) {
	// Force people to document this stuff
	assert.Equal(t, map[MessageType]string{
		Handshake:      "handshake",
		Message:        "message",
		RecvError:      "recvError",
		LightHouse:     "lightHouse",
		Test:           "test",
		CloseTunnel:    "closeTunnel",
		Control:        "control",
		HandshakeChunk: "handshakeChunk",
	}, typeMap)

	assert.Equal(t, map[MessageType]*map[MessageSubType]string{
		Message: {
			MessageNone:  "none",
			MessageRelay: "relay",
		},
		RecvError:   &subTypeNoneMap,
		LightHouse:  &subTypeNoneMap,
		Test:        &subTypeTestMap,
		CloseTunnel: &subTypeNoneMap,
		Handshake: {
			HandshakeIXPSK0: "ix_psk0",
			HandshakePQIX:   "pqix",
		},
		Control:        &subTypeNoneMap,
		HandshakeChunk: &subTypeNoneMap,
	}, subTypeMap)
}

// TestWireLayoutGolden pins the on-wire byte layout of the 16-byte header. If a
// field is reordered, resized, or the packing changes, these golden bytes break
// — a deliberate tripwire, since both ends and the chunk reassembler depend on
// the exact layout. Update intentionally, never to make a red test pass.
func TestWireLayoutGolden(t *testing.T) {
	cases := []struct {
		name string
		h    H
		want []byte
	}{
		{
			// version=1, type=Handshake(0), pqIX subtype(2), remoteIndex, counter
			name: "handshake_pqix",
			h:    H{Version: 1, Type: Handshake, Subtype: HandshakePQIX, RemoteIndex: 0x01020304, MessageCounter: 1},
			want: []byte{0x10, 0x02, 0, 0, 0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			// HandshakeChunk(7): RemoteIndex carries flightID, MessageCounter packs
			// count<<8|idx. Here flightID=0xAABBCCDD, count=7, idx=3 -> 0x0703.
			name: "handshake_chunk",
			h:    H{Version: 1, Type: HandshakeChunk, RemoteIndex: 0xAABBCCDD, MessageCounter: uint64(7)<<8 | 3},
			want: []byte{0x17, 0x00, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0, 0, 0, 0x07, 0x03},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.h.Encode(make([]byte, Len))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got, "wire layout drift")

			// Round-trips back to the same struct (Reserved is always 0 on the wire).
			var parsed H
			require.NoError(t, parsed.Parse(got))
			assert.Equal(t, tc.h, parsed)
		})
	}
}

// TestAllTypesDocumented fails if a MessageType constant is added without a
// typeMap entry (TypeName would return "unknown"). Catches the easy mistake of
// wiring a new packet type into the switch but forgetting the human-name table.
func TestAllTypesDocumented(t *testing.T) {
	for tp := Handshake; tp <= HandshakeChunk; tp++ {
		if _, ok := typeMap[tp]; !ok {
			t.Errorf("MessageType %d has no typeMap entry", tp)
		}
	}
}

func TestHeader_String(t *testing.T) {
	assert.Equal(
		t,
		"ver=100 type=test subtype=testRequest reserved=0x63 remoteindex=98 messagecounter=97",
		(&H{100, Test, TestRequest, 99, 98, 97}).String(),
	)
}

func TestHeader_MarshalJSON(t *testing.T) {
	b, err := (&H{100, Test, TestRequest, 99, 98, 97}).MarshalJSON()
	require.NoError(t, err)
	assert.Equal(
		t,
		"{\"messageCounter\":97,\"remoteIndex\":98,\"reserved\":99,\"subType\":\"testRequest\",\"type\":\"test\",\"version\":100}",
		string(b),
	)
}

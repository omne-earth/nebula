package noiseutil

import (
	"bytes"
	"testing"
)

// TestNewCipherStateAESGCMFromKey covers the post-quantum data-plane cipher built from a
// raw split key: two cipher states from the same key interoperate, and a wrong-length key
// is rejected.
func TestNewCipherStateAESGCMFromKey(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}

	enc, err := NewCipherStateAESGCMFromKey(key[:])
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewCipherStateAESGCMFromKey(key[:])
	if err != nil {
		t.Fatal(err)
	}

	ct, err := enc.EncryptDanger(nil, []byte("ad"), []byte("post-quantum"), 7, make([]byte, 12))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := dec.DecryptDanger(nil, []byte("ad"), ct, 7, make([]byte, 12))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("post-quantum")) {
		t.Fatalf("round-trip mismatch: %q", pt)
	}

	if _, err := NewCipherStateAESGCMFromKey([]byte("short")); err == nil {
		t.Fatal("expected error for a wrong-length key")
	}
}

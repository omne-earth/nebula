package noiseutil

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"github.com/flynn/noise"
)

// CipherStateAESGCM is the data-plane wrapper for the AES-GCM AEAD cipher.
// AES-GCM uses big-endian nonce encoding per the Noise spec.
type CipherStateAESGCM struct {
	c cipher.AEAD
}

// NewCipherStateAESGCM extracts the underlying AEAD from the post-handshake noise.CipherState.
// The caller is responsible for ensuring the noise cipher is actually AES-GCM,
// otherwise the type assertion still succeeds but the nonce endianness will be wrong on the wire.
func NewCipherStateAESGCM(s *noise.CipherState) *CipherStateAESGCM {
	return &CipherStateAESGCM{c: s.Cipher().(cipher.AEAD)}
}

// NewCipherStateAESGCMFromKey builds an AES-256-GCM data-plane CipherState from a raw
// 32-byte key. The post-quantum handshake (qp-nebula) derives raw transport keys from
// its KEM Split rather than a noise.CipherState, so it builds the data-plane cipher
// directly. The nonce endianness (big-endian, below) is identical to the noise path, so
// both peers and both handshake kinds agree on the wire.
func NewCipherStateAESGCMFromKey(key []byte) (*CipherStateAESGCM, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &CipherStateAESGCM{c: aead}, nil
}

func (s *CipherStateAESGCM) EncryptDanger(out, ad, plaintext []byte, n uint64, nb []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("no cipher state available to encrypt")
	}
	nb[0] = 0
	nb[1] = 0
	nb[2] = 0
	nb[3] = 0
	binary.BigEndian.PutUint64(nb[4:], n)
	return s.c.Seal(out, nb, plaintext, ad), nil
}

func (s *CipherStateAESGCM) DecryptDanger(out, ad, ciphertext []byte, n uint64, nb []byte) ([]byte, error) {
	if s == nil {
		return []byte{}, nil
	}
	nb[0] = 0
	nb[1] = 0
	nb[2] = 0
	nb[3] = 0
	binary.BigEndian.PutUint64(nb[4:], n)
	return s.c.Open(out, nb, ciphertext, ad)
}

func (s *CipherStateAESGCM) Overhead() int {
	if s == nil {
		return 0
	}
	return s.c.Overhead()
}

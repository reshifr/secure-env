package crypt

import (
	"github.com/reshifr/secure-env/core/crypt"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ChaCha20Poly1305AddLen = chacha20poly1305.Overhead
	ChaCha20Poly1305KeyLen = chacha20poly1305.KeySize
)

type ChaCha20Poly1305[CSPRNG crypt.CSPRNG] struct {
	csprng CSPRNG
}

func NewChaCha20Poly1305[CSPRNG crypt.CSPRNG](
	csprng CSPRNG) *ChaCha20Poly1305[CSPRNG] {
	return &ChaCha20Poly1305[CSPRNG]{csprng: csprng}
}

func (*ChaCha20Poly1305[CSPRNG]) KeyLen() uint32 {
	return ChaCha20Poly1305KeyLen
}

func (*ChaCha20Poly1305[CSPRNG]) IV(fixed []byte) (crypt.CipherIV, error) {
	return MakeIV96(fixed)
}

func (cipher *ChaCha20Poly1305[CSPRNG]) RandomIV() (crypt.CipherIV, error) {
	rawIV := [IV96Len]byte{}
	if err := cipher.csprng.Read(rawIV[:]); err != nil {
		return nil, err
	}
	return LoadIV96(rawIV[:])
}

func (cipher *ChaCha20Poly1305[CSPRNG]) Seal(iv crypt.CipherIV,
	key []byte, plaintext []byte) (crypt.CipherBuf, error) {
	if iv.Len() != IV96Len {
		return nil, crypt.ErrInvalidIVLen
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, crypt.ErrInvalidKeyLen
	}
	add := [ChaCha20Poly1305AddLen]byte{}
	if err := cipher.csprng.Read(add[:]); err != nil {
		return nil, err
	}
	nonce := iv.Invoke().Raw()
	ciphertext := aead.Seal(nil, nonce, plaintext, add[:])
	buf, err := MakeChaCha20Poly1305Buf(iv, add, ciphertext)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (cipher *ChaCha20Poly1305[CSPRNG]) Open(iv crypt.CipherIV,
	key []byte, cipherbuf crypt.CipherBuf) ([]byte, error) {
	if iv.Len() != IV96Len {
		return nil, crypt.ErrInvalidIVLen
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, crypt.ErrInvalidKeyLen
	}
	nonce := iv.Raw()
	add := cipherbuf.Add()
	ciphertext := cipherbuf.Ciphertext()
	plaintext, err := aead.Open(nil, nonce, ciphertext, add)
	if err != nil {
		return nil, crypt.ErrInvalidCipherOpenFailed
	}
	return plaintext, nil
}

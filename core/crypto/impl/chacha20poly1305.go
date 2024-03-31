package crypto_impl

import (
	"github.com/reshifr/secure-env/core/crypto"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ChaCha20Poly1305AddLen = chacha20poly1305.Overhead
	ChaCha20Poly1305KeyLen = chacha20poly1305.KeySize
)

type ChaCha20Poly1305[CSPRNG crypto.CSPRNG] struct {
	csprng CSPRNG
}

func NewChaCha20Poly1305[CSPRNG crypto.CSPRNG](
	csprng CSPRNG) *ChaCha20Poly1305[CSPRNG] {
	return &ChaCha20Poly1305[CSPRNG]{csprng: csprng}
}

func (*ChaCha20Poly1305[CSPRNG]) KeyLen() uint32 {
	return ChaCha20Poly1305KeyLen
}

func (*ChaCha20Poly1305[CSPRNG]) IV(fixed []byte) (crypto.CipherIV, error) {
	return MakeIV96(fixed)
}

func (cipher *ChaCha20Poly1305[CSPRNG]) RandomIV() (crypto.CipherIV, error) {
	rawIV := [IV96Len]byte{}
	if err := cipher.csprng.Read(rawIV[:]); err != nil {
		return nil, err
	}
	return LoadIV96(rawIV[:])
}

func (cipher *ChaCha20Poly1305[CSPRNG]) Seal(iv crypto.CipherIV,
	key []byte, plaintext []byte) (crypto.CipherBuf, error) {
	if iv.Len() != IV96Len {
		return nil, crypto.ErrInvalidIVLen
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, crypto.ErrInvalidKeyLen
	}
	add := [ChaCha20Poly1305AddLen]byte{}
	if err := cipher.csprng.Read(add[:]); err != nil {
		return nil, err
	}
	invokedIV := iv.Invoke()
	invokedRawIV := invokedIV.Raw()
	ciphertext := aead.Seal(nil, invokedRawIV, plaintext, add[:])
	buf, _ := MakeChaCha20Poly1305Buf(invokedIV, add, ciphertext)
	return buf, nil
}

func (cipher *ChaCha20Poly1305[CSPRNG]) Open(
	key []byte, cipherbuf crypto.CipherBuf) ([]byte, error) {
	rawIV := cipherbuf.RawIV()
	if len(rawIV) != IV96Len {
		return nil, crypto.ErrInvalidRawIVLen
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, crypto.ErrInvalidKeyLen
	}
	add := cipherbuf.Add()
	ciphertext := cipherbuf.Ciphertext()
	plaintext, err := aead.Open(nil, rawIV, ciphertext, add)
	if err != nil {
		return nil, crypto.ErrCipherAuthFailed
	}
	return plaintext, nil
}

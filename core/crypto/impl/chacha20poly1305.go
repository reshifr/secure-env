package crypto_impl

import (
	"github.com/reshifr/secure-env/core/crypto"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ChaCha20Poly1305ADLen  = chacha20poly1305.Overhead
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

func (cipher *ChaCha20Poly1305[CSPRNG]) Seal(iv crypto.CipherIV,
	key []byte, plaintext []byte) (crypto.CipherBuf, error) {
	if iv.Len() != IV96Len {
		return nil, crypto.ErrInvalidIVLen
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, crypto.ErrInvalidKeyLen
	}
	ad := [ChaCha20Poly1305ADLen]byte{}
	if err := cipher.csprng.Read(ad[:]); err != nil {
		return nil, err
	}
	invokedIV := iv.Invoke()
	invokedRawIV := invokedIV.Raw()
	ciphertext := aead.Seal(nil, invokedRawIV, plaintext, ad[:])
	buf, _ := MakeChaCha20Poly1305Buf(invokedRawIV, ad[:], ciphertext)
	return buf, nil
}

func (cipher *ChaCha20Poly1305[CSPRNG]) Open(
	key []byte, buf crypto.CipherBuf) ([]byte, error) {
	rawIV := buf.RawIV()
	if len(rawIV) != IV96Len {
		return nil, crypto.ErrInvalidRawIVLen
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, crypto.ErrInvalidKeyLen
	}
	ad := buf.AD()
	ciphertext := buf.Ciphertext()
	plaintext, err := aead.Open(nil, rawIV, ciphertext, ad)
	if err != nil {
		return nil, crypto.ErrCipherAuthFailed
	}
	return plaintext, nil
}

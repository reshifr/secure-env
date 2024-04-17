package crypto_impl

import (
	"github.com/reshifr/secure-env/core/crypto"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ChaChaPolyAEIVLen  = 12
	ChaChaPolyAEKeyLen = 32
)

type ChaChaPolyAE struct{}

func (ChaChaPolyAE) KeyLen() uint32 {
	return ChaChaPolyAEKeyLen
}

func (ChaChaPolyAE) Seal(
	iv crypto.IV, key []byte, plaintext []byte) ([]byte, error) {
	if iv.Len() != ChaChaPolyAEIVLen {
		return nil, crypto.ErrInvalidIVLen
	}
	chacha, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, crypto.ErrInvalidKeyLen
	}
	rawIV := iv.Invoke()
	ciphertext := chacha.Seal(nil, rawIV, plaintext, nil)
	buf := make([]byte, ChaChaPolyAEIVLen+len(ciphertext))
	copy(buf, rawIV)
	copy(buf[ChaChaPolyAEIVLen:], ciphertext)
	return buf, nil
}

func (ChaChaPolyAE) Open(key []byte, buf []byte) ([]byte, error) {
	if len(buf) < ChaChaPolyAEIVLen {
		return nil, crypto.ErrInvalidBufLayout
	}
	chacha, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, crypto.ErrInvalidKeyLen
	}
	rawIV := buf[:ChaChaPolyAEIVLen]
	ciphertext := buf[ChaChaPolyAEIVLen:]
	plaintext, err := chacha.Open(nil, rawIV, ciphertext, nil)
	if err != nil {
		return nil, crypto.ErrAuthFailed
	}
	return plaintext, nil
}

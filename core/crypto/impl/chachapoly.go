package crypto_impl

import (
	"github.com/reshifr/secure-env/core/crypto"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ChaChaPolyIVLen  = 12
	ChaChaPolyKeyLen = 32
)

type ChaChaPoly struct{}

func (ChaChaPoly) KeyLen() uint32 {
	return ChaChaPolyKeyLen
}

func (ChaChaPoly) Seal(iv crypto.IV,
	key []byte, plaintext []byte) ([]byte, error) {
	if iv.Len() != ChaChaPolyIVLen {
		return nil, crypto.ErrInvalidIVLen
	}
	chacha, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, crypto.ErrInvalidKeyLen
	}
	rawIV := iv.Invoke()
	ciphertext := chacha.Seal(nil, rawIV, plaintext, nil)
	buf := make([]byte, ChaChaPolyIVLen+len(ciphertext))
	copy(buf, rawIV)
	copy(buf[ChaChaPolyIVLen:], ciphertext)
	return buf, nil
}

func (ChaChaPoly) Open(key []byte, buf []byte) ([]byte, error) {
	if len(buf) < ChaChaPolyIVLen {
		return nil, crypto.ErrInvalidBufLayout
	}
	chacha, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, crypto.ErrInvalidKeyLen
	}
	rawIV := buf[:ChaChaPolyIVLen]
	ciphertext := buf[ChaChaPolyIVLen:]
	plaintext, err := chacha.Open(nil, rawIV, ciphertext, nil)
	if err != nil {
		return nil, crypto.ErrAuthFailed
	}
	return plaintext, nil
}

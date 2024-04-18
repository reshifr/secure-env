package crypto_impl

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/reshifr/secure-env/core/crypto"
)

const (
	AESGCMIVLen  = 12
	AESGCMKeyLen = 32
)

type AESGCM struct{}

func (AESGCM) KeyLen() uint32 {
	return AESGCMKeyLen
}

func (AESGCM) Seal(iv crypto.IV,
	key []byte, plaintext []byte) ([]byte, error) {
	if iv.Len() != AESGCMIVLen {
		return nil, crypto.ErrInvalidIVLen
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, crypto.ErrInvalidKeyLen
	}
	rawIV := iv.Invoke()
	aesgcm, _ := cipher.NewGCM(aes)
	ciphertext := aesgcm.Seal(nil, rawIV, plaintext, nil)
	buf := make([]byte, AESGCMIVLen+len(ciphertext))
	copy(buf, rawIV)
	copy(buf[AESGCMIVLen:], ciphertext)
	return buf, nil
}

func (AESGCM) Open(key []byte, buf []byte) ([]byte, error) {
	if len(buf) < AESGCMIVLen {
		return nil, crypto.ErrInvalidBufLayout
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, crypto.ErrInvalidKeyLen
	}
	rawIV := buf[:AESGCMIVLen]
	ciphertext := buf[AESGCMIVLen:]
	aesgcm, _ := cipher.NewGCM(aes)
	plaintext, err := aesgcm.Open(nil, rawIV, ciphertext, nil)
	if err != nil {
		return nil, crypto.ErrAuthFailed
	}
	return plaintext, nil
}

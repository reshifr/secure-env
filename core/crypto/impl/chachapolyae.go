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

func (ChaChaPolyAE) MakeBuf(rawIV []byte,
	ciphertext []byte) (crypto.CipherBuf, error) {
	return MakeAE96Buf(rawIV, ciphertext)
}

func (ChaChaPolyAE) LoadBuf(rawBuf []byte) (crypto.CipherBuf, error) {
	return LoadAE96Buf(rawBuf)
}

func (ae ChaChaPolyAE) Seal(iv crypto.CipherIV,
	key []byte, plaintext []byte) (crypto.CipherBuf, error) {
	if iv.Len() != ChaChaPolyAEIVLen {
		return nil, crypto.ErrInvalidIVLen
	}
	chacha, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, crypto.ErrInvalidKeyLen
	}
	rawIV := iv.Invoke()
	ciphertext := chacha.Seal(nil, rawIV, plaintext, nil)
	buf, _ := ae.MakeBuf(rawIV, ciphertext)
	return buf, nil
}

func (ChaChaPolyAE) Open(
	key []byte, buf crypto.CipherBuf) ([]byte, error) {
	rawIV := buf.RawIV()
	if len(rawIV) != ChaChaPolyAEIVLen {
		return nil, crypto.ErrInvalidIVLen
	}
	chacha, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, crypto.ErrInvalidKeyLen
	}
	ciphertext := buf.Ciphertext()
	plaintext, err := chacha.Open(nil, rawIV, ciphertext, nil)
	if err != nil {
		return nil, crypto.ErrCipherAuthFailed
	}
	return plaintext, nil
}

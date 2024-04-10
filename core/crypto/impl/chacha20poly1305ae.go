package crypto_impl

import (
	"github.com/reshifr/secure-env/core/crypto"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ChaCha20Poly1305AEKeyLen = 32
)

type ChaCha20Poly1305AE struct{}

func (ChaCha20Poly1305AE) IVLen() uint32 {
	return IV96Len
}

func (ChaCha20Poly1305AE) IVFixedLen() uint32 {
	return IV96FixedLen
}

func (ChaCha20Poly1305AE) KeyLen() uint32 {
	return ChaCha20Poly1305AEKeyLen
}

func (ChaCha20Poly1305AE) MakeIV(fixed []byte) (crypto.CipherIV, error) {
	return MakeIV96(fixed)
}

func (ChaCha20Poly1305AE) LoadIV(rawIV []byte) (crypto.CipherIV, error) {
	return LoadIV96(rawIV)
}

func (ChaCha20Poly1305AE) MakeBuf(rawIV []byte,
	ciphertext []byte) (crypto.CipherBuf, error) {
	return MakeIV96Buf(rawIV, ciphertext)
}

func (ChaCha20Poly1305AE) LoadBuf(rawBuf []byte) (crypto.CipherBuf, error) {
	return LoadIV96Buf(rawBuf)
}

func (ChaCha20Poly1305AE) Encrypt(iv crypto.CipherIV,
	key []byte, plaintext []byte) (crypto.CipherBuf, error) {
	if iv.Len() != IV96Len {
		return nil, crypto.ErrInvalidIVLen
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, crypto.ErrInvalidKeyLen
	}
	invokedIV := iv.Invoke()
	invokedRawIV := invokedIV.Raw()
	ciphertext := aead.Seal(nil, invokedRawIV, plaintext, nil)
	buf, _ := MakeIV96Buf(invokedRawIV, ciphertext)
	return buf, nil
}

func (ChaCha20Poly1305AE) Decrypt(
	key []byte, buf crypto.CipherBuf) ([]byte, error) {
	rawIV := buf.RawIV()
	if len(rawIV) != IV96Len {
		return nil, crypto.ErrInvalidRawIVLen
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, crypto.ErrInvalidKeyLen
	}
	ciphertext := buf.Ciphertext()
	plaintext, err := aead.Open(nil, rawIV, ciphertext, nil)
	if err != nil {
		return nil, crypto.ErrCipherAuthFailed
	}
	return plaintext, nil
}

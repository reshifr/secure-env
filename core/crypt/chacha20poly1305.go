package crypt

import "golang.org/x/crypto/chacha20poly1305"

const (
	ChaCha20Poly1305AddLen = chacha20poly1305.Overhead
	ChaCha20Poly1305KeyLen = chacha20poly1305.KeySize
)

type ChaCha20Poly1305[CSPRNG ICSPRNG] struct {
	csprng CSPRNG
}

func NewChaCha20Poly1305[CSPRNG ICSPRNG](
	csprng CSPRNG) *ChaCha20Poly1305[CSPRNG] {
	return &ChaCha20Poly1305[CSPRNG]{csprng: csprng}
}

func (*ChaCha20Poly1305[CSPRNG]) KeyLen() uint32 {
	return ChaCha20Poly1305KeyLen
}

func (*ChaCha20Poly1305[CSPRNG]) IV(fixed []byte) (ICipherIV, error) {
	return MakeIV96(fixed)
}

func (cipher *ChaCha20Poly1305[CSPRNG]) RandomIV() (ICipherIV, error) {
	rawIV := [IV96Len]byte{}
	if err := cipher.csprng.Read(rawIV[:]); err != nil {
		return nil, err
	}
	return LoadIV96(rawIV[:])
}

func (cipher *ChaCha20Poly1305[CSPRNG]) Seal(iv ICipherIV,
	key []byte, plaintext []byte) (ICipherBuf, error) {
	if iv.Len() != IV96Len {
		return nil, ErrInvalidIVLen
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, ErrInvalidKeyLen
	}
	add := [ChaCha20Poly1305AddLen]byte{}
	if err := cipher.csprng.Read(add[:]); err != nil {
		return nil, err
	}
	nonce := iv.Invoke().Raw()
	ciphertext := aead.Seal(nil, nonce, plaintext, add[:])
	buf := MakeChaCha20Poly1305Buf(add, ciphertext)
	return buf, nil
}

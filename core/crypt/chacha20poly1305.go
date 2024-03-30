package crypt

import "golang.org/x/crypto/chacha20poly1305"

const (
	ChaCha20Poly1305AddLen  = chacha20poly1305.Overhead
	ChaCha20Poly1305KeyLen  = chacha20poly1305.KeySize
	ChaCha20Poly1305SaltLen = 32
)

type ChaCha20Poly1305[KDF IKDF, CSPRNG ICSPRNG] struct {
	kdf    KDF
	csprng CSPRNG
}

func OpenChaCha20Poly1305[KDF IKDF, CSPRNG ICSPRNG](
	kdf KDF, csprng CSPRNG) *ChaCha20Poly1305[KDF, CSPRNG] {
	return &ChaCha20Poly1305[KDF, CSPRNG]{kdf: kdf, csprng: csprng}
}

func (*ChaCha20Poly1305[KDF, CSPRNG]) AddLen() uint32 {
	return ChaCha20Poly1305AddLen
}

func (*ChaCha20Poly1305[KDF, CSPRNG]) KeyLen() uint32 {
	return ChaCha20Poly1305KeyLen
}

func (*ChaCha20Poly1305[KDF, CSPRNG]) SaltLen() uint32 {
	return ChaCha20Poly1305SaltLen
}

func (*ChaCha20Poly1305[KDF, CSPRNG]) IV(fixed []byte) (ICipherIV, error) {
	return MakeIV96(fixed)
}

func (cipher *ChaCha20Poly1305[KDF, CSPRNG]) RandomIV() (ICipherIV, error) {
	rawIV := [IV96Len]byte{}
	if err := cipher.csprng.Read(rawIV[:]); err != nil {
		return nil, err
	}
	return LoadIV96(rawIV[:])
}

func (cipher *ChaCha20Poly1305[KDF, CSPRNG]) Seal(iv ICipherIV,
	passphrase string, plaintext []byte) (ICipherBuf, error) {
	if iv.Len() != IV96Len {
		return nil, ErrInvalidIVLen
	}
	add := [ChaCha20Poly1305AddLen]byte{}
	if err := cipher.csprng.Read(add[:]); err != nil {
		return nil, err
	}
	salt := [ChaCha20Poly1305SaltLen]byte{}
	if err := cipher.csprng.Read(salt[:]); err != nil {
		return nil, err
	}
	key := cipher.kdf.Key(passphrase, salt[:], ChaCha20Poly1305KeyLen)
	aead, _ := chacha20poly1305.New(key)
	nonce := iv.Invoke().Raw()
	ciphertext := aead.Seal(nil, nonce, plaintext, add[:])
	buf := MakeChaCha20Poly1305Buf(add, salt, ciphertext)
	return buf, nil
}

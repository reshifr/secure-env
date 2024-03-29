package crypt

import "golang.org/x/crypto/chacha20poly1305"

const (
	chacha20poly1305IVLen   int    = 12
	chacha20poly1305AddLen  int    = 16
	chacha20Poly1305KeyLen  uint32 = 32
	chacha20Poly1305SaltLen int    = 32
)

type ChaCha20Poly1305[KDF IKDF, CSPRNG ICSPRNG] struct {
	kdf    KDF
	csprng CSPRNG
}

func OpenChaCha20Poly1305[KDF IKDF, CSPRNG ICSPRNG](
	kdf KDF, csprng CSPRNG) *ChaCha20Poly1305[KDF, CSPRNG] {
	return &ChaCha20Poly1305[KDF, CSPRNG]{kdf: kdf, csprng: csprng}
}

func (cipher *ChaCha20Poly1305[KDF, CSPRNG]) Encrypt(
	iv IIV, passphrase string, plaintext []byte) ([]byte, error) {
	if iv.Len() != chacha20poly1305IVLen {
		return nil, ErrInvalidIVLen
	}
	add := [chacha20poly1305AddLen]byte{}
	if err := cipher.csprng.Read(add[:]); err != nil {
		return nil, err
	}
	salt := [chacha20Poly1305SaltLen]byte{}
	if err := cipher.csprng.Read(salt[:]); err != nil {
		return nil, err
	}
	key := cipher.kdf.Key(passphrase, salt[:], chacha20Poly1305KeyLen)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, ErrInvalidKeyLen
	}
	iv.Invoke()
	ciphertext := []byte{}
	aead.Seal(ciphertext, iv.Raw(), plaintext, add[:])
	return ciphertext, nil
}

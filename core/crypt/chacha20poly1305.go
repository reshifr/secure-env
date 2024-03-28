package crypt

import "golang.org/x/crypto/chacha20poly1305"

const (
	chacha20Poly1305SaltLen = 32
)

type Chacha20Poly1305[KDF IKDF, CSPRNG ICSPRNG] struct {
	kdf    KDF
	csprng CSPRNG
}

func NewChacha20Poly1305[KDF IKDF, CSPRNG ICSPRNG](
	kdf KDF, csprng CSPRNG) *Chacha20Poly1305[KDF, CSPRNG] {
	return &Chacha20Poly1305[KDF, CSPRNG]{kdf: kdf, csprng: csprng}
}

func (cipher *Chacha20Poly1305[KDF, CSPRNG]) Encrypt(
	passphrase string, iv IIV, plaintext []byte) ([]byte, error) {
	ciphertext := []byte{}
	if iv.Len() != chacha20poly1305.NonceSize {
		return ciphertext, ErrIVInvalidLen
	}
	salt, err := cipher.csprng.Make(chacha20Poly1305SaltLen)
	if err != nil {
		return ciphertext, err
	}
	add, err := cipher.csprng.Make(chacha20poly1305.Overhead)
	if err != nil {
		return ciphertext, err
	}
	k := cipher.kdf.Key(passphrase, salt, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.New(k)
	if err != nil {
		return ciphertext, ErrCipherInvalidKeyLen
	}

	iv.Invoke()
	nonce := iv.Raw()
	aead.Seal(ciphertext, nonce, plaintext, add)
	return ciphertext, nil
}

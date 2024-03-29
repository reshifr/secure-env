package crypt

import "golang.org/x/crypto/chacha20poly1305"

type MultiAccessKey[KDF IKDF, CSPRNG ICSPRNG] struct {
	bitmapIDAllocator uint64
	masterIV          IIV
	masterKey         []byte
	privateKeys       map[uint8]struct {
		add        []byte
		salt       []byte
		ciphertext []byte
	}
}

func OpenMultiAccessKey[KDF IKDF, CSPRNG ICSPRNG](
	kdf KDF, csprng CSPRNG) (*MultiAccessKey[KDF, CSPRNG], error) {
	masterKey := [chacha20poly1305.KeySize]byte{}
	if err := csprng.Read(masterKey[:]); err != nil {
		return nil, ErrReadEntropyFailed
	}
	key := &MultiAccessKey[KDF, CSPRNG]{masterKey: masterKey[:]}
	return key, nil
}

func (key *MultiAccessKey[KDF, CSPRNG]) Add(
	iv IIV, passphrase string) (int, error) {
	// ciphertext := key.public
	// if iv.Len() != chacha20poly1305.NonceSize {
	// 	return ciphertext, ErrIVInvalidLen
	// }
	// salt := [chacha20Poly1305SaltLen]byte{}
	// if err := cipher.csprng.Read(salt[:]); err != nil {
	// 	return ciphertext, err
	// }
	// add := [chacha20poly1305.Overhead]byte{}
	// if err := cipher.csprng.Read(add[:]); err != nil {
	// 	return ciphertext, err
	// }
	// k := cipher.kdf.Key(passphrase, salt[:], chacha20poly1305.KeySize)
	// aead, err := chacha20poly1305.New(k)
	// if err != nil {
	// 	return ciphertext, ErrCipherInvalidKeyLen
	// }

	// iv.Invoke()
	// nonce := iv.Raw()
	// aead.Seal(ciphertext, nonce, plaintext, add[:])
	return 0, nil
}

// func (cipher *Chacha20Poly1305[KDF, CSPRNG]) Encrypt(
// 	passphrase string, iv IIV, plaintext []byte) ([]byte, error) {
// 	ciphertext := []byte{}
// 	if iv.Len() != chacha20poly1305.NonceSize {
// 		return ciphertext, ErrIVInvalidLen
// 	}
// 	salt := [chacha20Poly1305SaltLen]byte{}
// 	if err := cipher.csprng.Read(salt[:]); err != nil {
// 		return ciphertext, err
// 	}
// 	add := [chacha20poly1305.Overhead]byte{}
// 	if err := cipher.csprng.Read(add[:]); err != nil {
// 		return ciphertext, err
// 	}
// 	k := cipher.kdf.Key(passphrase, salt[:], chacha20poly1305.KeySize)
// 	aead, err := chacha20poly1305.New(k)
// 	if err != nil {
// 		return ciphertext, ErrCipherInvalidKeyLen
// 	}

// 	iv.Invoke()
// 	nonce := iv.Raw()
// 	aead.Seal(ciphertext, nonce, plaintext, add[:])
// 	return ciphertext, nil
// }

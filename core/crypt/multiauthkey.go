package crypt

type MultiAuthKey[KDF IKDF, CSPRNG ICSPRNG] struct {
	bitmap      uint64
	sharedIV    IIV
	privateIV   IIV
	sharedKey   []byte
	privateKeys map[uint8]struct {
		add        []byte
		salt       []byte
		ciphertext []byte
	}
}

// func MakeMultiAuthKey[KDF IKDF, CSPRNG ICSPRNG](kdf KDF,
// 	csprng CSPRNG, passphrase string) (*MultiAuthKey[KDF, CSPRNG], error) {
// 	publicKey := [chacha20poly1305.KeySize]byte{}
// 	if err := csprng.Read(publicKey[:]); err != nil {
// 		return nil, ErrCSPRNGRead
// 	}
// 	authKey := &MultiAuthKey[KDF, CSPRNG]{publicKey: publicKey[:]}
// 	return authKey, nil
// }

func (key *MultiAuthKey[KDF, CSPRNG]) Add(passphrase string) (int, error) {
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

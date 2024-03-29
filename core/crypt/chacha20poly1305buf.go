package crypt

// type ChaCha20Poly1305Buf[IV IIV, KDF IKDF, CSPRNG ICSPRNG] struct {
// 	kdf       KDF
// 	csprng    CSPRNG
// 	dataBlock struct {
// 		iv         IV
// 		add        []byte
// 		salt       []byte
// 		ciphertext []byte
// 	}
// 	authBlocks struct {
// 		iv         IV
// 		add        []byte
// 		salt       []byte
// 		ciphertext []byte
// 	}]
// }

// func MakeChaCha20Poly1305Buf[IV IIV, KDF IKDF, CSPRNG ICSPRNG](
// 	kdf KDF, csprng CSPRNG) *ChaCha20Poly1305Buf[IV, KDF, CSPRNG] {

// 	return nil
// 	// return &Chacha20Poly1305[KDF, CSPRNG]{
// 	// 	kdf:    kdf,
// 	// 	csprng: csprng,
// 	// }
// }

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

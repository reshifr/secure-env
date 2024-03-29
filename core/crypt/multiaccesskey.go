package crypt

type MultiAccessKey[KDF IKDF, CSPRNG ICSPRNG, Cipher ICipher] struct {
	kdf         KDF
	csprng      CSPRNG
	cipher      Cipher
	masterIV    ICipherIV
	masterKey   []byte
	bitmap      uint64
	privateKeys map[int8]*ICipherBuf
}

// func OpenMultiAccessKey[IV IIV, KDF IKDF, CSPRNG ICSPRNG, Cipher ICipher](
// 	kdf KDF, csprng CSPRNG, cipher Cipher, iv IIV, passphrase string) (
// 	*MultiAccessKey[IV, KDF, CSPRNG, Cipher], error) {
// 	masterIV
// 	masterKey, err := csprng.Make(int(cipher.KeyLen()))
// 	if err != nil {
// 		return nil, ErrReadEntropyFailed
// 	}
// 	key := &MultiAccessKey[KDF, CSPRNG, Cipher]{
// 		kdf:       kdf,
// 		csprng:    csprng,
// 		cipher:    cipher,
// 		masterKey: masterKey,
// 	}
// 	return key, nil
// }

// func (key *MultiAccessKey[KDF, CSPRNG, Cipher]) id() int8 {
// 	i := int8(0)
// 	n := ^key.bitmap
// 	if n >= uint64(0x0000000100000000) {
// 		i += 32
// 		n >>= 32
// 	}
// 	if n >= uint64(0x0000000000010000) {
// 		i += 16
// 		n >>= 16
// 	}
// 	if n >= uint64(0x0000000000000100) {
// 		i += 8
// 		n >>= 8
// 	}
// 	if n >= uint64(0x0000000000000010) {
// 		i += 4
// 		n >>= 4
// 	}
// 	if n >= uint64(0x0000000000000004) {
// 		i += 2
// 		n >>= 2
// 	}
// 	if n >= uint64(0x0000000000000002) {
// 		i += 1
// 		n >>= 1
// 	}
// 	key.bitmap |= uint64(1) << i
// 	return i
// }

// func (key *MultiAccessKey[KDF, CSPRNG, Cipher]) Add(
// 	iv IIV, passphrase string) (int8, error) {
// 	if ^key.bitmap == 0 {
// 		return -1, ErrKeyExceedsLimit
// 	}
// 	cipherBuf, err := key.cipher.Encrypt(iv, passphrase, key.masterKey)
// 	if err != nil {
// 		return -1, nil
// 	}
// 	id := key.id()
// 	key.privateKeys[id] = cipherBuf
// 	return id, nil
// }

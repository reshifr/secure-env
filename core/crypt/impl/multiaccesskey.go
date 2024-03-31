package crypt

import (
	"github.com/reshifr/secure-env/core/crypt"
)

const (
	MultiAccessKeySaltLen = 16
)

type makEncryptedKey struct {
	salt      [MultiAccessKeySaltLen]byte
	cipherbuf crypt.CipherBuf
}

type MultiAccessKey[KDF crypt.KDF, CSPRNG crypt.CSPRNG, Cipher crypt.Cipher] struct {
	kdf           KDF
	csprng        CSPRNG
	cipher        Cipher
	bitmap        uint64
	iv            crypt.CipherIV
	sharedKey     []byte
	encryptedKeys map[int8]makEncryptedKey
}

func NewMultiAccessKey[KDF crypt.KDF, CSPRNG crypt.CSPRNG, Cipher crypt.Cipher](
	kdf KDF, csprng CSPRNG, cipher Cipher, iv crypt.CipherIV) (
	*MultiAccessKey[KDF, CSPRNG, Cipher], error) {
	sharedKey, err := csprng.Make(int(cipher.KeyLen()))
	if err != nil {
		return nil, crypt.ErrReadEntropyFailed
	}
	mak := &MultiAccessKey[KDF, CSPRNG, Cipher]{
		kdf:       kdf,
		csprng:    csprng,
		cipher:    cipher,
		iv:        iv,
		sharedKey: sharedKey,
	}
	return mak, nil
}

func (mak *MultiAccessKey[KDF, CSPRNG, Cipher]) id() int8 {
	i := int8(0)
	n := ^mak.bitmap
	if n >= uint64(0x0000000100000000) {
		i += 32
		n >>= 32
	}
	if n >= uint64(0x0000000000010000) {
		i += 16
		n >>= 16
	}
	if n >= uint64(0x0000000000000100) {
		i += 8
		n >>= 8
	}
	if n >= uint64(0x0000000000000010) {
		i += 4
		n >>= 4
	}
	if n >= uint64(0x0000000000000004) {
		i += 2
		n >>= 2
	}
	if n >= uint64(0x0000000000000002) {
		i += 1
		n >>= 1
	}
	mak.bitmap |= uint64(1) << i
	return i
}

func (mak *MultiAccessKey[KDF, CSPRNG, Cipher]) Add(
	iv crypt.CipherIV, passphrase string) (int8, error) {
	if ^mak.bitmap == 0 {
		return -1, crypt.ErrKeyExceedsLimit
	}
	salt := [MultiAccessKeySaltLen]byte{}
	if err := mak.csprng.Read(salt[:]); err != nil {
		return -1, err
	}
	privateKey := mak.kdf.Key(passphrase, salt[:], mak.cipher.KeyLen())
	cipherbuf, err := mak.cipher.Seal(iv, privateKey, mak.sharedKey)
	if err != nil {
		return -1, err
	}
	id := mak.id()
	mak.encryptedKeys[id] = makEncryptedKey{salt: salt, cipherbuf: cipherbuf}
	return id, nil
}

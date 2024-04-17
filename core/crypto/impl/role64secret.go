package crypto_impl

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	avl "github.com/emirpasic/gods/v2/trees/avltree"
	"github.com/reshifr/secure-env/core/crypto"
)

const (
	Role64SecretMaxId      = 63
	Role64SecretSaltLen    = 16
	Role64SecretBitmapSize = 8
	Role64SecretBufLenSize = 1
)

type Role64SecretSharedKey struct {
	salt []byte
	buf  crypto.CipherBuf
}

type Role64Secret[
	KDF crypto.KDF,
	RNG crypto.CSPRNG,
	Cipher crypto.CipherAE] struct {
	kdf        KDF
	rng        RNG
	cipher     Cipher
	bitmap     uint64
	mainKey    []byte
	sharedKeys *avl.Tree[int8, Role64SecretSharedKey]
}

func MakeRole64Secret[
	KDF crypto.KDF,
	RNG crypto.CSPRNG,
	Cipher crypto.CipherAE](
	kdf KDF,
	rng RNG,
	cipher Cipher) (*Role64Secret[KDF, RNG, Cipher], error) {
	key, err := rng.Block(int(cipher.KeyLen()))
	if err != nil {
		return nil, err
	}
	secret := &Role64Secret[KDF, RNG, Cipher]{
		kdf:        kdf,
		rng:        rng,
		cipher:     cipher,
		mainKey:    key,
		sharedKeys: avl.New[int8, Role64SecretSharedKey](),
	}
	return secret, err
}

func LoadRole64Secret[
	KDF crypto.KDF,
	RNG crypto.CSPRNG,
	Cipher crypto.CipherAE](
	kdf KDF,
	rng RNG,
	cipher Cipher,
	id int,
	passphrase string,
	rawSecret []byte) (*Role64Secret[KDF, RNG, Cipher], error) {
	if id < 0 || id > Role64SecretMaxId {
		return nil, crypto.ErrInvalidSecretId
	}

	mainLen := Role64SecretBitmapSize + Role64SecretBufLenSize
	if len(rawSecret) < mainLen {
		return nil, crypto.ErrBrokenSecretIntegrity
	}

	bitmap := binary.BigEndian.Uint64(rawSecret)
	if bitmap == 0 {
		return nil, crypto.ErrBrokenSecretIntegrity
	}

	i := Role64SecretBitmapSize
	bufLen := int(rawSecret[i])
	i += Role64SecretBufLenSize
	n := bits.OnesCount64(bitmap)
	sharedKeyLen := Role64SecretSaltLen + bufLen
	sharedBlockLen := sharedKeyLen * n
	if len(rawSecret[i:]) != sharedBlockLen {
		return nil, crypto.ErrBrokenSecretIntegrity
	}

	order := bitmap << (Role64SecretMaxId - id)
	if (order & 0x8000000000000000) == 0 {
		return nil, crypto.ErrIdDoesNotExist
	}
	pBuf := bits.OnesCount64(order) - 1
	iBuf := i + pBuf*sharedKeyLen
	salt := rawSecret[iBuf : iBuf+Role64SecretSaltLen]
	iBuf += Role64SecretSaltLen
	buf, _ := cipher.LoadBuf(rawSecret[iBuf : iBuf+bufLen])

	key := kdf.Key(passphrase, salt, cipher.KeyLen())
	mainKey, err := cipher.Open(key, buf)
	if err != nil {
		return nil, err
	}

	it := bitmap
	sharedKeys := avl.New[int8, Role64SecretSharedKey]()
	for p := 0; it != 0; p++ {
		if p == pBuf {
			sharedKey := Role64SecretSharedKey{salt: salt, buf: buf}
			sharedKeys.Put(int8(id), sharedKey)
			i += sharedKeyLen
			it &= it - 1
			continue
		}
		salt := rawSecret[i : i+Role64SecretSaltLen]
		i += Role64SecretSaltLen
		buf, _ := cipher.LoadBuf(rawSecret[i : i+bufLen])
		sharedKey := Role64SecretSharedKey{salt: salt, buf: buf}
		id := bits.TrailingZeros64(it)
		sharedKeys.Put(int8(id), sharedKey)
		i += bufLen
		it &= it - 1
	}

	secret := &Role64Secret[KDF, RNG, Cipher]{
		kdf:        kdf,
		rng:        rng,
		cipher:     cipher,
		bitmap:     bitmap,
		mainKey:    mainKey,
		sharedKeys: sharedKeys,
	}
	return secret, nil
}

func (secret *Role64Secret[KDF, CSPRNG, Cipher]) DEBUG() {
	fmt.Printf("kdf=%v\n", secret.kdf)
	fmt.Printf("rng=%v\n", secret.rng)
	fmt.Printf("cipher=%v\n", secret.cipher)
	fmt.Printf("bitmap=%064b\n", secret.bitmap)
	fmt.Printf("mainKey=%x\n", secret.mainKey)
	it := secret.sharedKeys.Iterator()
	for it.Next() {
		fmt.Printf(
			"sharedKey[%v]=%x %x\n",
			it.Key(),
			it.Value().salt,
			it.Value().buf.Raw(),
		)
	}
}

func (secret *Role64Secret[KDF, RNG, Cipher]) Add(
	iv crypto.CipherIV, passphrase string) (int, error) {
	if secret.bitmap == 0xffffffffffffffff {
		return -1, crypto.ErrSharingExceedsLimit
	}
	salt, err := secret.rng.Block(Role64SecretSaltLen)
	if err != nil {
		return -1, err
	}
	key := secret.kdf.Key(passphrase, salt, secret.cipher.KeyLen())
	buf, err := secret.cipher.Seal(iv, key, secret.mainKey)
	if err != nil {
		return -1, err
	}
	id := bits.TrailingZeros64(^secret.bitmap)
	sharedKey := Role64SecretSharedKey{salt: salt, buf: buf}
	secret.bitmap |= 1 << id
	secret.sharedKeys.Put(int8(id), sharedKey)
	return id, nil
}

// // func (secret *Role64Secret[KDF, CSPRNG, Cipher]) Find(userId int) bool {
// // 	return (secret.bitmap & (1 << userId)) != 0
// // }

func (secret *Role64Secret[KDF, RNG, Cipher]) Del(id int) {
	secret.bitmap &= ^(1 << id)
	secret.sharedKeys.Remove(int8(id))
}

// func (secret *Role64Secret[KDF, CSPRNG, Cipher]) Encrypt(
// 	plaintext []byte) crypto.CipherBuf {
// 	buf, _ := secret.cipher.Encrypt(secret.mainIV, secret.mainKey, plaintext)
// 	return buf
// }

// func (secret *Role64Secret[KDF, CSPRNG, Cipher]) Decrypt(
// 	buf crypto.CipherBuf) ([]byte, error) {
// 	return secret.cipher.Decrypt(secret.mainKey, buf)
// }

func (secret *Role64Secret[KDF, RNG, Cipher]) Raw() []byte {
	if secret.bitmap == 0 {
		return nil
	}
	bufLen := 0
	sharedKeysLen := 0
	it := secret.sharedKeys.Iterator()
	if it.Next() {
		sharedKey := it.Value()
		bufLen = sharedKey.buf.Len()
		n := secret.sharedKeys.Size()
		sharedKeysLen = Role64SecretSaltLen*n + bufLen*n
	}

	rawLen := Role64SecretBitmapSize + Role64SecretBufLenSize + sharedKeysLen
	raw := make([]byte, rawLen)

	binary.BigEndian.PutUint64(raw, secret.bitmap)
	i := Role64SecretBitmapSize
	raw[i] = byte(bufLen)
	i += Role64SecretBufLenSize
	for it.Begin(); it.Next(); {
		sharedKey := it.Value()
		copy(raw[i:], sharedKey.salt)
		i += Role64SecretSaltLen
		copy(raw[i:], sharedKey.buf.Raw())
		i += bufLen
	}
	return raw
}

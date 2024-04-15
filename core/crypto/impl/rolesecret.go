package crypto_impl

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	avl "github.com/emirpasic/gods/v2/trees/avltree"
	"github.com/reshifr/secure-env/core/crypto"
)

const (
	RoleSecretMaxId      = 63
	RoleSecretSaltLen    = 16
	RoleSecretBitmapSize = 8
	RoleSecretBufLenSize = 1
)

type RoleSecretSharedKey struct {
	salt []byte
	buf  crypto.CipherBuf
}

type RoleSecret[
	KDF crypto.KDF,
	RNG crypto.CSPRNG,
	Cipher crypto.CipherAE] struct {
	kdf        KDF
	rng        RNG
	cipher     Cipher
	bitmap     uint64
	mainKey    []byte
	sharedKeys *avl.Tree[int8, RoleSecretSharedKey]
}

func MakeRoleSecret[KDF crypto.KDF, RNG crypto.CSPRNG, Cipher crypto.CipherAE](
	kdf KDF, rng RNG, cipher Cipher) (*RoleSecret[KDF, RNG, Cipher], error) {
	key, err := rng.Block(int(cipher.KeyLen()))
	if err != nil {
		return nil, err
	}
	secret := &RoleSecret[KDF, RNG, Cipher]{
		kdf:        kdf,
		rng:        rng,
		cipher:     cipher,
		mainKey:    key,
		sharedKeys: avl.New[int8, RoleSecretSharedKey](),
	}
	return secret, err
}

func LoadRoleSecret[KDF crypto.KDF, RNG crypto.CSPRNG, Cipher crypto.CipherAE](
	kdf KDF,
	rng RNG,
	cipher Cipher,
	rawSecret []byte,
	id int,
	passphrase string) (*RoleSecret[KDF, RNG, Cipher], error) {
	if id < 0 || id > RoleSecretMaxId {
		return nil, crypto.ErrInvalidSecretId
	}

	mainLen := RoleSecretBitmapSize + RoleSecretBufLenSize
	if len(rawSecret) < mainLen {
		return nil, crypto.ErrBrokenSecretIntegrity
	}

	bitmap := binary.BigEndian.Uint64(rawSecret)
	if bitmap == 0 {
		return nil, crypto.ErrBrokenSecretIntegrity
	}

	i := RoleSecretBitmapSize
	bufLen := int(rawSecret[i])
	i += RoleSecretBufLenSize
	n := bits.OnesCount64(bitmap)
	sharedKeyLen := RoleSecretSaltLen + bufLen
	sharedBlockLen := sharedKeyLen * n
	if len(rawSecret[i:]) != sharedBlockLen {
		return nil, crypto.ErrBrokenSecretIntegrity
	}

	order := bitmap << (RoleSecretMaxId - id)
	if (order & 0x8000000000000000) == 0 {
		return nil, crypto.ErrIdDoesNotExist
	}
	pBuf := bits.OnesCount64(order) - 1
	iBuf := i + pBuf*sharedKeyLen
	salt := rawSecret[iBuf : iBuf+RoleSecretSaltLen]
	iBuf += RoleSecretSaltLen
	buf, _ := cipher.LoadBuf(rawSecret[iBuf : iBuf+bufLen])

	key := kdf.Key(passphrase, salt, cipher.KeyLen())
	mainKey, err := cipher.Open(key, buf)
	if err != nil {
		return nil, err
	}

	it := bitmap
	sharedKeys := avl.New[int8, RoleSecretSharedKey]()
	for p := 0; it != 0; p++ {
		if p == pBuf {
			sharedKey := RoleSecretSharedKey{salt: salt, buf: buf}
			sharedKeys.Put(int8(id), sharedKey)
			i += sharedKeyLen
			it &= it - 1
			continue
		}
		salt := rawSecret[i : i+RoleSecretSaltLen]
		i += RoleSecretSaltLen
		buf, _ := cipher.LoadBuf(rawSecret[i : i+bufLen])
		sharedKey := RoleSecretSharedKey{salt: salt, buf: buf}
		id := bits.TrailingZeros64(it)
		sharedKeys.Put(int8(id), sharedKey)
		i += bufLen
		it &= it - 1
	}

	secret := &RoleSecret[KDF, RNG, Cipher]{
		kdf:        kdf,
		rng:        rng,
		cipher:     cipher,
		bitmap:     bitmap,
		mainKey:    mainKey,
		sharedKeys: sharedKeys,
	}
	return secret, nil
}

func (secret *RoleSecret[KDF, CSPRNG, Cipher]) DEBUG() {
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

func (secret *RoleSecret[KDF, RNG, Cipher]) Add(
	iv crypto.CipherIV, passphrase string) (int, error) {
	if secret.bitmap == 0xffffffffffffffff {
		return -1, crypto.ErrSharingExceedsLimit
	}
	salt, err := secret.rng.Block(RoleSecretSaltLen)
	if err != nil {
		return -1, err
	}
	key := secret.kdf.Key(passphrase, salt, secret.cipher.KeyLen())
	buf, err := secret.cipher.Seal(iv, key, secret.mainKey)
	if err != nil {
		return -1, err
	}
	id := bits.TrailingZeros64(^secret.bitmap)
	sharedKey := RoleSecretSharedKey{salt: salt, buf: buf}
	secret.bitmap |= 1 << id
	secret.sharedKeys.Put(int8(id), sharedKey)
	return id, nil
}

// // func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Find(userId int) bool {
// // 	return (secret.bitmap & (1 << userId)) != 0
// // }

func (secret *RoleSecret[KDF, RNG, Cipher]) Del(id int) {
	secret.bitmap &= ^(1 << id)
	secret.sharedKeys.Remove(int8(id))
}

// func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Encrypt(
// 	plaintext []byte) crypto.CipherBuf {
// 	buf, _ := secret.cipher.Encrypt(secret.mainIV, secret.mainKey, plaintext)
// 	return buf
// }

// func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Decrypt(
// 	buf crypto.CipherBuf) ([]byte, error) {
// 	return secret.cipher.Decrypt(secret.mainKey, buf)
// }

func (secret *RoleSecret[KDF, RNG, Cipher]) Raw() []byte {
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
		sharedKeysLen = RoleSecretSaltLen*n + bufLen*n
	}

	rawLen := RoleSecretBitmapSize + RoleSecretBufLenSize + sharedKeysLen
	raw := make([]byte, rawLen)

	binary.BigEndian.PutUint64(raw, secret.bitmap)
	i := RoleSecretBitmapSize
	raw[i] = byte(bufLen)
	i += RoleSecretBufLenSize
	for it.Begin(); it.Next(); {
		sharedKey := it.Value()
		copy(raw[i:], sharedKey.salt)
		i += RoleSecretSaltLen
		copy(raw[i:], sharedKey.buf.Raw())
		i += bufLen
	}
	return raw
}

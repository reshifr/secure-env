package crypto_impl

import (
	"encoding/binary"
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

// func LoadRoleSecret[
// 	KDF crypto.KDF,
// 	CSPRNG crypto.CSPRNG,
// 	Cipher crypto.Cipher](
// 	kdf KDF,
// 	csprng CSPRNG,
// 	cipher Cipher,
// 	raw []byte,
// 	id int,
// 	passphrase string) (*RoleSecret[KDF, CSPRNG, Cipher], error) {
// 	if id < 0 || id > RoleSecretMaxId {
// 		return nil, crypto.ErrInvalidSecretId
// 	}
// 	ivLen := int(cipher.IVLen())
// 	mainBlockLen := RoleSecretBitmapSize + RoleSecretBufLenSize + ivLen
// 	if len(raw) < mainBlockLen {
// 		return nil, crypto.ErrInvalidBufferLayout
// 	}
// 	i := 0
// 	bitmap := binary.BigEndian.Uint64(raw[i:])
// 	if bitmap == 0 {
// 		return nil, crypto.ErrInvalidBufferLayout
// 	}

// 	i += RoleSecretBitmapSize
// 	bufLen := int(binary.BigEndian.Uint64(raw[i:]))
// 	i += RoleSecretBufLenSize
// 	n := bits.OnesCount64(bitmap)
// 	sharedKeyLen := bufLen + RoleSecretSaltLen
// 	sharedBlockLen := sharedKeyLen * n
// 	if len(raw[i:]) != sharedBlockLen {
// 		return nil, crypto.ErrInvalidBufferLayout
// 	}

// 	order := bitmap << (RoleSecretMaxId - id)
// 	if (order & 0x8000000000000000) == 0 {
// 		return nil, crypto.ErrIdDoesNotExist
// 	}
// 	pBuf := bits.OnesCount64(order) - 1
// 	iBuf := i + pBuf*sharedKeyLen
// 	salt := raw[iBuf : iBuf+RoleSecretSaltLen]
// 	iBuf += RoleSecretSaltLen
// 	buf, _ := cipher.LoadBuf(raw[iBuf : iBuf+bufLen])

// 	key := kdf.Key(passphrase, salt, cipher.KeyLen())
// 	mainKey, err := cipher.Decrypt(key, buf)
// 	if err != nil {
// 		return nil, err
// 	}

// 	it := bitmap
// 	rawIV := raw[i : i+ivLen]
// 	i += ivLen
// 	sharedKeys := avl.New[int, RoleSecretSharedKey]()
// 	for p := 0; it != 0; p++ {
// 		if p == pBuf {
// 			sharedKey := RoleSecretSharedKey{salt: salt, buf: buf}
// 			sharedKeys.Put(id, sharedKey)
// 			i += sharedKeyLen
// 			it &= it - 1
// 			continue
// 		}
// 		salt := raw[i : i+RoleSecretSaltLen]
// 		i += RoleSecretSaltLen
// 		buf, _ := cipher.LoadBuf(raw[i : i+bufLen])
// 		i += bufLen
// 		sharedKey := RoleSecretSharedKey{salt: salt, buf: buf}
// 		bufId := bits.TrailingZeros64(it)
// 		sharedKeys.Put(bufId, sharedKey)
// 		it &= it - 1
// 	}

// 	iv, _ := cipher.LoadIV(rawIV)
// 	secret := &RoleSecret[KDF, CSPRNG, Cipher]{
// 		kdf:        kdf,
// 		csprng:     csprng,
// 		cipher:     cipher,
// 		bitmap:     bitmap,
// 		mainIV:     iv,
// 		mainKey:    mainKey,
// 		sharedKeys: sharedKeys,
// 	}
// 	return secret, nil
// }

// func (secret *RoleSecret[KDF, CSPRNG, Cipher]) DEBUG() {
// 	fmt.Printf("kdf=%v\n", secret.kdf)
// 	fmt.Printf("csprng=%v\n", secret.csprng)
// 	fmt.Printf("cipher=%v\n", secret.cipher)
// 	fmt.Printf("bitmap=%064b\n", secret.bitmap)
// 	fmt.Printf("mainIV=%x\n", secret.mainIV.Raw())
// 	fmt.Printf("mainKey=%x\n", secret.mainKey)

// 	skit := secret.sharedKeys.Iterator()
// 	for skit.Begin(); skit.Next(); {
// 		fmt.Printf(
// 			"sharedKey[%v]=%x %x\n",
// 			skit.Key(),
// 			skit.Value().salt,
// 			skit.Value().buf.Raw(),
// 		)
// 	}
// }

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

// func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Del(id int) {
// 	secret.bitmap &= ^(1 << id)
// 	secret.sharedKeys.Remove(id)
// }

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

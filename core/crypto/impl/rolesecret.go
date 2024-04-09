package crypto_impl

import (
	"encoding/binary"
	"math/bits"

	avl "github.com/emirpasic/gods/v2/trees/avltree"
	"github.com/reshifr/secure-env/core/crypto"
)

const (
	RoleSecretSaltLen    = 16
	RoleSecretBitmapSize = 8
	RoleSecretBufLenSize = 8
)

type RoleSecretSharedKey struct {
	buf  crypto.CipherBuf
	salt [RoleSecretSaltLen]byte
}

type RoleSecret[
	KDF crypto.KDF,
	CSPRNG crypto.CSPRNG,
	Cipher crypto.Cipher] struct {
	kdf    KDF
	csprng CSPRNG
	cipher Cipher
	bitmap uint64
	iv     crypto.CipherIV
	key    []byte
	shared *avl.Tree[int8, RoleSecretSharedKey]
}

func MakeRoleSecret[
	KDF crypto.KDF,
	CSPRNG crypto.CSPRNG,
	Cipher crypto.Cipher](
	kdf KDF,
	csprng CSPRNG,
	cipher Cipher) (*RoleSecret[KDF, CSPRNG, Cipher], error) {
	key, err := csprng.Block(int(cipher.KeyLen()))
	if err != nil {
		return nil, err
	}
	rawIV, err := csprng.Block(int(cipher.IVLen()))
	if err != nil {
		return nil, err
	}
	iv, _ := cipher.LoadIV(rawIV)
	secret := &RoleSecret[KDF, CSPRNG, Cipher]{
		kdf:    kdf,
		csprng: csprng,
		cipher: cipher,
		iv:     iv,
		key:    key,
		shared: avl.New[int8, RoleSecretSharedKey](),
	}
	return secret, nil
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
// 	if id < 0 || id > 63 {
// 		return nil, crypto.ErrInvalidSecretId
// 	}
// 	ivLen := int(cipher.IVLen())
// 	mainBlockLen := RoleSecretBitmapSize + RoleSecretBufLenSize + ivLen
// 	if len(raw) < mainBlockLen {
// 		return nil, crypto.ErrInvalidBufferLayout
// 	}
// 	i := 0
// 	bitmap := binary.BigEndian.Uint64(raw[i:])
// 	i += RoleSecretBitmapSize
// 	bufLen := int(binary.BigEndian.Uint64(raw[i:]))
// 	i += RoleSecretBufLenSize
// 	rawIV := raw[i : i+ivLen]
// 	i += ivLen

// 	n := bits.OnesCount64(bitmap)
// 	userBlockLen := bufLen*n + RoleSecretSaltLen*n
// 	if len(raw[i:]) != userBlockLen {
// 		return nil, crypto.ErrInvalidBufferLayout
// 	}

// 	bufOrder := bitmap << (63 - id)
// 	if bufOrder == 0 {
// 		return nil, crypto.ErrInvalidSecretId
// 	}
// 	pBuf := bits.OnesCount64(bufOrder) - 1
// 	iBuf := i + (pBuf * d)

// 	// userKey = kdf.Key()
// 	// key, err :=

// 	iv, _ := cipher.LoadIV(rawIV)
// 	secret := &RoleSecret[KDF, CSPRNG, Cipher]{
// 		kdf:      kdf,
// 		csprng:   csprng,
// 		cipher:   cipher,
// 		iv:       iv,
// 		key:      key,
// 		userKeys: make(map[int8]roleSecretUserKey),
// 	}
// 	return nil, nil
// }

func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Add(
	iv crypto.CipherIV, passphrase string) (int, error) {
	if secret.bitmap == 0xffffffffffffffff {
		return -1, crypto.ErrSharingExceedsLimit
	}
	salt := [RoleSecretSaltLen]byte{}
	if err := secret.csprng.Read(salt[:]); err != nil {
		return -1, err
	}
	key := secret.kdf.Key(passphrase, salt[:], secret.cipher.KeyLen())
	buf, err := secret.cipher.Encrypt(iv, key, secret.key)
	if err != nil {
		return -1, err
	}
	id := bits.TrailingZeros64(^secret.bitmap)
	sharedKey := RoleSecretSharedKey{buf: buf, salt: salt}
	secret.bitmap |= 1 << id
	secret.shared.Put(int8(id), sharedKey)
	return id, nil
}

// func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Find(userId int8) bool {
// 	return (secret.bitmap & (1 << userId)) != 0
// }

// func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Del(userId int8) {
// 	delete(secret.userKeys, userId)
// 	secret.bitmap &= ^(1 << userId)
// }

func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Encrypt(
	plaintext []byte) (crypto.CipherBuf, error) {
	return secret.cipher.Encrypt(secret.iv, secret.key, plaintext)
}

func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Decrypt(
	buf crypto.CipherBuf) ([]byte, error) {
	return secret.cipher.Decrypt(secret.key, buf)
}

func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Raw() []byte {
	n := secret.shared.Size()
	if n == 0 {
		return nil
	}
	bufLen := 0
	allBufLen := 0
	allSaltLen := 0
	ivLen := int(secret.cipher.IVLen())
	it := secret.shared.Iterator()
	for it.Begin(); it.Next(); {
		sharedKey := it.Value()
		bufLen = int(sharedKey.buf.Len())
		allBufLen += bufLen * n
		allSaltLen += RoleSecretSaltLen * n
		break
	}
	rawLen := RoleSecretBitmapSize + ivLen +
		RoleSecretBufLenSize + allSaltLen + allBufLen
	raw := make([]byte, rawLen)

	i := 0
	binary.BigEndian.PutUint64(raw[i:], secret.bitmap)
	i += RoleSecretBitmapSize
	binary.BigEndian.PutUint64(raw[i:], uint64(bufLen))
	i += RoleSecretBufLenSize
	copy(raw[i:], secret.iv.Raw())
	i += ivLen
	for it.Begin(); it.Next(); {
		sharedKey := it.Value()
		copy(raw[i:], sharedKey.salt[:])
		i += RoleSecretSaltLen
		copy(raw[i:], sharedKey.buf.Raw())
		i += bufLen
	}
	return raw
}

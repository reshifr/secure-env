package crypto_impl

import (
	"encoding/binary"

	"github.com/reshifr/secure-env/core/bits"
	"github.com/reshifr/secure-env/core/crypto"
)

const (
	RoleSecretSaltLen    = 16
	RoleSecretBitmapSize = 8
	RoleSecretBufLenSize = 8
)

type roleSecretUserKey struct {
	buf  crypto.CipherBuf
	salt [RoleSecretSaltLen]byte
}

type RoleSecret[
	KDF crypto.KDF,
	CSPRNG crypto.CSPRNG,
	Cipher crypto.Cipher] struct {
	kdf      KDF
	csprng   CSPRNG
	cipher   Cipher
	bitmap   uint64
	iv       crypto.CipherIV
	key      []byte
	userKeys map[int8]roleSecretUserKey
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
		kdf:      kdf,
		csprng:   csprng,
		cipher:   cipher,
		iv:       iv,
		key:      key,
		userKeys: make(map[int8]roleSecretUserKey),
	}
	return secret, nil
}

func LoadRoleSecret[
	KDF crypto.KDF,
	CSPRNG crypto.CSPRNG,
	Cipher crypto.Cipher](
	kdf KDF,
	csprng CSPRNG,
	cipher Cipher,
	passphrase string) (*RoleSecret[KDF, CSPRNG, Cipher], error) {
	return nil, nil
}

func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Add(
	iv crypto.CipherIV, passphrase string) (int, error) {
	if secret.bitmap == 0xffffffffffffffff {
		return -1, crypto.ErrSharingExceedsLimit
	}
	salt := [RoleSecretSaltLen]byte{}
	if err := secret.csprng.Read(salt[:]); err != nil {
		return -1, err
	}
	userKey := secret.kdf.Key(passphrase, salt[:], secret.cipher.KeyLen())
	buf, err := secret.cipher.Encrypt(iv, userKey, secret.key)
	if err != nil {
		return -1, err
	}
	id := bits.CTZ64(^secret.bitmap)
	secret.bitmap |= 1 << id
	secret.userKeys[int8(id)] = roleSecretUserKey{buf: buf, salt: salt}
	return id, nil
}

func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Find(userId int8) bool {
	return (secret.bitmap & (1 << userId)) != 0
}

func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Del(userId int8) {
	delete(secret.userKeys, userId)
	secret.bitmap &= ^(1 << userId)
}

func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Encrypt(
	plaintext []byte) (crypto.CipherBuf, error) {
	return secret.cipher.Encrypt(secret.iv, secret.key, plaintext)
}

func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Decrypt(
	buf crypto.CipherBuf) ([]byte, error) {
	return secret.cipher.Decrypt(secret.key, buf)
}

func (secret *RoleSecret[KDF, CSPRNG, Cipher]) Raw() []byte {
	n := len(secret.userKeys)
	if n == 0 {
		return nil
	}
	bufLen := 0
	allBufLen := 0
	allSaltLen := 0
	ivLen := int(secret.cipher.IVLen())
	for _, userKey := range secret.userKeys {
		bufLen = int(userKey.buf.Len())
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
	for _, userKey := range secret.userKeys {
		copy(raw[i:], userKey.salt[:])
		i += RoleSecretSaltLen
		copy(raw[i:], userKey.buf.Raw())
		i += bufLen
	}
	return raw
}

package crypto_impl

import (
	"github.com/reshifr/secure-env/core/crypto"
)

const (
	RoleSecretSaltLen = 16
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
	fixed, err := csprng.Block(int(cipher.IVFixedLen()))
	if err != nil {
		return nil, err
	}
	iv, _ := cipher.MakeIV(fixed)
	sec := &RoleSecret[KDF, CSPRNG, Cipher]{
		kdf:      kdf,
		csprng:   csprng,
		cipher:   cipher,
		iv:       iv,
		key:      key,
		userKeys: make(map[int8]roleSecretUserKey),
	}
	return sec, nil
}

func (sec *RoleSecret[KDF, CSPRNG, Cipher]) userId() int8 {
	i := int8(0)
	n := ^sec.bitmap
	if n >= 0x0000000100000000 {
		i += 32
		n >>= 32
	}
	if n >= 0x0000000000010000 {
		i += 16
		n >>= 16
	}
	if n >= 0x0000000000000100 {
		i += 8
		n >>= 8
	}
	if n >= 0x0000000000000010 {
		i += 4
		n >>= 4
	}
	if n >= 0x0000000000000004 {
		i += 2
		n >>= 2
	}
	if n >= 0x0000000000000002 {
		i += 1
		n >>= 1
	}
	sec.bitmap |= 1 << i
	return i
}

func (sec *RoleSecret[KDF, CSPRNG, Cipher]) Add(
	userIV crypto.CipherIV, passphrase string) (int8, error) {
	if ^sec.bitmap == 0 {
		return -1, crypto.ErrSharingExceedsLimit
	}
	salt := [RoleSecretSaltLen]byte{}
	if err := sec.csprng.Read(salt[:]); err != nil {
		return -1, err
	}
	userKey := sec.kdf.Key(passphrase, salt[:], sec.cipher.KeyLen())
	buf, err := sec.cipher.Seal(userIV, userKey, sec.key)
	if err != nil {
		return -1, err
	}
	id := sec.userId()
	sec.userKeys[id] = roleSecretUserKey{buf: buf, salt: salt}
	return id, nil
}

func (sec *RoleSecret[KDF, CSPRNG, Cipher]) Find(userId int8) bool {
	return (sec.bitmap & (1 << userId)) != 0
}

func (sec *RoleSecret[KDF, CSPRNG, Cipher]) Del(userId int8) {
	delete(sec.userKeys, userId)
	sec.bitmap &= ^(1 << userId)
}

func (sec *RoleSecret[KDF, CSPRNG, Cipher]) Seal(
	plaintext []byte) (crypto.CipherBuf, error) {
	return sec.cipher.Seal(sec.iv, sec.key, plaintext)
}

func (sec *RoleSecret[KDF, CSPRNG, Cipher]) Open(
	buf crypto.CipherBuf) ([]byte, error) {
	return sec.cipher.Open(sec.key, buf)
}

func (sec *RoleSecret[KDF, CSPRNG, Cipher]) Raw() {
	// block := mak
}

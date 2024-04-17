package crypto_impl

import "github.com/reshifr/secure-env/core/crypto"

const (
	RoleAccessSaltLen = 16
)

type RoleAccess[
	KDF crypto.KDF,
	RNG crypto.CSPRNG,
	Cipher crypto.CipherAE,
	IV crypto.CipherIV] struct {
	kdf    KDF
	rng    RNG
	cipher Cipher
	iv     IV
}

func NewRoleAccess[
	KDF crypto.KDF,
	RNG crypto.CSPRNG,
	Cipher crypto.CipherAE,
	IV crypto.CipherIV](
	kdf KDF,
	rng RNG,
	cipher Cipher,
	iv IV) *RoleAccess[KDF, RNG, Cipher, IV] {
	return &RoleAccess[KDF, RNG, Cipher, IV]{
		kdf:    kdf,
		rng:    rng,
		cipher: cipher,
		iv:     iv,
	}
}

func (acc *RoleAccess[KDF, RNG, Cipher, IV]) Secret(
	passphrase string) (*RoleSecret, error) {
	keyLen := acc.cipher.KeyLen()
	accKey, err := acc.rng.Block(int(keyLen))
	if err != nil {
		return nil, err
	}
	salt := [RoleAccessSaltLen]byte{}
	if err := acc.rng.Read(salt[:]); err != nil {
		return nil, err
	}
	key := acc.kdf.Key(passphrase, salt[:], keyLen)
	buf, err := acc.cipher.Seal(acc.iv, key, accKey)
	if err != nil {
		return nil, err
	}
	secret := MakeRoleSecret(accKey, salt, buf)
	return secret, nil
}

func (acc *RoleAccess[KDF, RNG, Cipher, IV]) Inherit(
	parentPassphrase string, childPassphrase string) {

}

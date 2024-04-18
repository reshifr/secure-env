package crypto_impl

import "github.com/reshifr/secure-env/core/crypto"

const (
	RoleAccessSaltLen = 16
)

type RoleAccess[
	KDF crypto.KDF,
	RNG crypto.RNG,
	IV crypto.IV,
	Cipher crypto.AE] struct {
	kdf    KDF
	rng    RNG
	iv     IV
	cipher Cipher
}

func NewRoleAccess[
	KDF crypto.KDF,
	RNG crypto.RNG,
	IV crypto.IV,
	Cipher crypto.AE](
	kdf KDF,
	rng RNG,
	iv IV,
	cipher Cipher) *RoleAccess[KDF, RNG, IV, Cipher] {
	return &RoleAccess[KDF, RNG, IV, Cipher]{
		kdf:    kdf,
		rng:    rng,
		iv:     iv,
		cipher: cipher,
	}
}

// func (acc *RoleAccess[KDF, RNG, IV, Cipher]) Secret(
// 	passphrase string) (*RoleSecret, error) {
// 	keyLen := acc.cipher.KeyLen()
// 	accKey, err := acc.rng.Block(int(keyLen))
// 	if err != nil {
// 		return nil, err
// 	}
// 	salt := [RoleAccessSaltLen]byte{}
// 	if err := acc.rng.Read(salt[:]); err != nil {
// 		return nil, err
// 	}
// 	key := acc.kdf.Key(passphrase, salt[:], keyLen)
// 	buf, err := acc.cipher.Seal(acc.iv, key, accKey)
// 	if err != nil {
// 		return nil, err
// 	}
// 	secret := MakeRoleSecret(accKey, salt, buf)
// 	return secret, nil
// }

// func (acc *RoleAccess[KDF, RNG, IV, Cipher]) Inherit(
// 	parentPassphrase string, childPassphrase string) {
// }

package crypto_impl

import (
	"github.com/reshifr/secure-env/core/crypto"
)

const (
	RoleAuthorizerSaltLen = 16
)

type RoleAuthorizer[
	KDF crypto.KDF,
	RNG crypto.RNG,
	Cipher crypto.AE] struct {
	kdf    KDF
	rng    RNG
	cipher Cipher
}

func NewRoleAuthorizer[
	KDF crypto.KDF,
	RNG crypto.RNG,
	Cipher crypto.AE](
	kdf KDF, rng RNG, cipher Cipher) RoleAuthorizer[KDF, RNG, Cipher] {
	return RoleAuthorizer[KDF, RNG, Cipher]{
		kdf:    kdf,
		rng:    rng,
		cipher: cipher,
	}
}

func (authorizer RoleAuthorizer[KDF, RNG, Cipher]) Make(
	iv crypto.IV, passphrase []byte, keyLen uint32) ([]byte, []byte, error) {
	accessKey, err := authorizer.rng.Block(int(keyLen))
	if err != nil {
		return nil, nil, err
	}
	salt := [RoleAuthorizerSaltLen]byte{}
	if err := authorizer.rng.Read(salt[:]); err != nil {
		return nil, nil, err
	}
	block, err := authorizer.sealAccessKey(iv, passphrase, salt, accessKey)
	if err != nil {
		return nil, block, err
	}
	return accessKey, block, err
}

func (authorizer RoleAuthorizer[KDF, RNG, Cipher]) Open(
	passphrase []byte, block []byte) ([]byte, error) {
	if len(block) < RoleAuthorizerSaltLen {
		return nil, crypto.ErrInvalidBlockLen
	}
	salt := block[:RoleAuthorizerSaltLen]
	buf := block[RoleAuthorizerSaltLen:]
	key := authorizer.kdf.Key(passphrase, salt, authorizer.cipher.KeyLen())
	accessKey, err := authorizer.cipher.Open(key, buf)
	if err != nil {
		return nil, err
	}
	return accessKey, nil
}

func (authorizer RoleAuthorizer[KDF, RNG, Cipher]) Inherit(
	iv crypto.IV,
	passphrase []byte,
	childPassphrase []byte,
	block []byte) ([]byte, []byte, error) {
	accessKey, err := authorizer.Open(passphrase, block)
	if err != nil {
		return nil, nil, err
	}
	salt := [RoleAuthorizerSaltLen]byte{}
	if err := authorizer.rng.Read(salt[:]); err != nil {
		return nil, nil, err
	}
	childBlock, err := authorizer.sealAccessKey(
		iv, childPassphrase, salt, accessKey)
	return accessKey, childBlock, err
}

func (authorizer RoleAuthorizer[KDF, RNG, Cipher]) sealAccessKey(
	iv crypto.IV,
	passphrase []byte,
	salt [RoleAuthorizerSaltLen]byte,
	accessKey []byte) (block []byte, err error) {
	key := authorizer.kdf.Key(passphrase, salt[:], authorizer.cipher.KeyLen())
	buf, err := authorizer.cipher.Seal(iv, key, accessKey)
	if err != nil {
		return nil, err
	}
	block = make([]byte, RoleAuthorizerSaltLen+len(buf))
	copy(block, salt[:])
	copy(block[RoleAuthorizerSaltLen:], buf)
	return block, nil
}

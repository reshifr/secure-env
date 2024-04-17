package crypto_impl

import "github.com/reshifr/secure-env/core/crypto"

type RoleSecret struct {
	key   []byte
	block []byte
}

func MakeRoleSecret[Buf crypto.CipherBuf](
	key []byte, salt [RoleAccessSaltLen]byte, buf Buf) *RoleSecret {
	block := make([]byte, RoleAccessSaltLen+buf.Len())
	copy(block, salt[:])
	copy(block, buf.Raw())
	return &RoleSecret{
		key:   key,
		block: block,
	}
}

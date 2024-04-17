package crypto_impl

type RoleSecret struct {
	key   []byte
	block []byte
}

func MakeRoleSecret(
	key []byte, salt [RoleAccessSaltLen]byte, buf []byte) *RoleSecret {
	block := make([]byte, RoleAccessSaltLen+len(buf))
	copy(block, salt[:])
	copy(block, buf)
	return &RoleSecret{
		key:   key,
		block: block,
	}
}

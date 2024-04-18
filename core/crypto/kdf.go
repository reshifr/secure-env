package crypto

type KDF interface {
	Key(passphrase []byte, salt []byte, keyLen uint32) (key []byte)
}

package crypt

type KDF interface {
	Key(passphrase string, salt []byte, keyLen uint32) (key []byte)
}

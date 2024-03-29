package crypt

type IKDF interface {
	Key(passphrase string, salt []byte, keyLen uint32) (key []byte)
}

package crypt

type IKDF interface {
	PassphraseKey(passphrase string, salt []byte, keyLen uint32) (key []byte)
}

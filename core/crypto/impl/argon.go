package crypto_impl

import (
	"golang.org/x/crypto/argon2"
)

const (
	ArgonTime    = 7
	ArgonMemory  = 65537
	ArgonThreads = 7
)

type Argon struct{}

func (Argon) Key(passphrase []byte, salt []byte, keyLen uint32) []byte {
	key := argon2.Key(
		passphrase,
		salt,
		ArgonTime,
		ArgonMemory,
		ArgonThreads,
		keyLen,
	)
	return key
}

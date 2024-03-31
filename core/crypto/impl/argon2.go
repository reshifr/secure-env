package crypto_impl

import (
	"golang.org/x/crypto/argon2"
)

const (
	Argon2Time    = 7
	Argon2Memory  = 65537
	Argon2Threads = 7
)

type Argon2 struct{}

func (Argon2) Key(passphrase string, salt []byte, keyLen uint32) []byte {
	key := argon2.Key(
		[]byte(passphrase),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		keyLen,
	)
	return key
}

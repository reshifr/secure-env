package crypt

import (
	"golang.org/x/crypto/argon2"
)

const (
	argon2Time    uint32 = 7
	argon2Memory  uint32 = 65537
	argon2Threads uint8  = 7
)

type Argon2 struct{}

func (Argon2) Key(passphrase string, salt []byte, keyLen uint32) []byte {
	key := argon2.Key(
		[]byte(passphrase),
		salt,
		argon2Time,
		argon2Memory,
		argon2Threads,
		keyLen,
	)
	return key
}

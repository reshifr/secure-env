package crypt

import (
	"golang.org/x/crypto/argon2"
)

const (
	argon2Time    uint32 = 8
	argon2Memory  uint32 = 64 * 1024
	argon2Threads uint8  = 8
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

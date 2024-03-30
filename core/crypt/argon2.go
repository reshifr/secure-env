package crypt

import (
	"golang.org/x/crypto/argon2"
)

const (
	Argon2Time    uint32 = 7
	Argon2Memory  uint32 = 65537
	Argon2Threads uint8  = 7
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

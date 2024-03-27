package std

import (
	"golang.org/x/crypto/argon2"
)

type Argon2 struct{}

func (h Argon2) Key(
	password []byte,
	salt []byte,
	time uint32,
	memory uint32,
	threads uint8,
	keyLen uint32) []byte {
	k := argon2.Key(password, salt, time, memory, threads, keyLen)
	return k
}

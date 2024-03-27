package crypt

import (
	"github.com/reshifr/secure-env/core"
)

const (
	kdfTime    uint32 = 8
	kdfMemory  uint32 = 64 * 1024
	kdfThreads uint8  = 4
)

type KDF[H core.IArgon2] struct {
	h H
}

func NewKDF[H core.IArgon2](h H) KDF[H] {
	return KDF[H]{h: h}
}

func (kdf *KDF[H]) PassphraseKey(
	passphrase string, salt []byte, keyLen uint32) []byte {
	k := kdf.h.Key(
		[]byte(passphrase),
		salt,
		kdfTime,
		kdfMemory,
		kdfThreads,
		keyLen,
	)
	return k
}

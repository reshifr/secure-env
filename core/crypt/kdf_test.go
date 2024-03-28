package crypt

import (
	"encoding/hex"
	"testing"

	"github.com/reshifr/secure-env/core/std"
	"github.com/stretchr/testify/assert"
)

func Test_KDF_PassphraseKey(t *testing.T) {
	t.Parallel()
	passphrase := "5B=lYQQyK~JFld+M"
	salt := []byte("fZbwz?1ji#KRR1pA.id-Vr/DAu/8RC8P")
	expK, _ := hex.DecodeString("41471cf52163a491ba27966bfc096505")

	argon2 := std.Argon2{}
	kdf := NewKDF(argon2)
	k := kdf.PassphraseKey(passphrase, salt, 16)
	assert.Equal(t, expK, k)
}

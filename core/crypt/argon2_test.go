package crypt

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Argon2_Key(t *testing.T) {
	t.Parallel()
	passphrase := "5B=lYQQyK~JFld+M"
	salt := []byte("fZbwz?1ji#KRR1pA.id-Vr/DAu/8RC8P")
	expK, _ := hex.DecodeString("41471cf52163a491ba27966bfc096505")

	kdf := Argon2{}
	k := kdf.Key(passphrase, salt, 16)
	assert.Equal(t, expK, k)
}

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
	expKey, _ := hex.DecodeString("9a35a4dc6ddd05f9658de4421f54fa02")

	kdf := Argon2{}
	key := kdf.Key(passphrase, salt, 16)
	assert.Equal(t, expKey, key)
}

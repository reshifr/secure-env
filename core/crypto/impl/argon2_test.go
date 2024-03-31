package crypto_impl

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Argon2_Key(t *testing.T) {
	t.Parallel()
	t.Run("Empty input", func(t *testing.T) {
		t.Parallel()
		passphrase := ""
		expKey, _ := hex.DecodeString("5ec0f1251a896d18d4675829f916639f")
		kdf := Argon2{}
		key := kdf.Key(passphrase, nil, 16)
		assert.Equal(t, expKey, key)
	})
	t.Run("Filled input", func(t *testing.T) {
		t.Parallel()
		passphrase := "5B=lYQQyK~JFld+M"
		salt := []byte("fZbwz?1ji#KRR1pA.id-Vr/DAu/8RC8P")
		expKey, _ := hex.DecodeString("b29a74d664d598df31d73d4a795bb985")
		kdf := Argon2{}
		key := kdf.Key(passphrase, salt, 16)
		assert.Equal(t, expKey, key)
	})
}

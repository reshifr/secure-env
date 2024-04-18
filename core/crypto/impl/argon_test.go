package crypto_impl

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Argon_Key(t *testing.T) {
	t.Parallel()
	kdf := Argon{}

	t.Run("Empty input", func(t *testing.T) {
		t.Parallel()
		expKey, _ := hex.DecodeString("5ec0f1251a896d18d4675829f916639f")

		key := kdf.Key(nil, nil, 16)
		assert.Equal(t, expKey, key)
	})
	t.Run("Filled input", func(t *testing.T) {
		t.Parallel()
		passphrase := []byte("+DF7Rc-X/MOYjkNj")
		salt, _ := hex.DecodeString("fe05fd6e139ceeb6b732fe6ea913aace")
		expKey, _ := hex.DecodeString("4069e3739afe0c508914454de5bfe255")

		key := kdf.Key(passphrase, salt, 16)
		assert.Equal(t, expKey, key)
	})
}

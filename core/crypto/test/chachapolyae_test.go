package crypto_test

import (
	"crypto/rand"
	"testing"

	c "github.com/reshifr/secure-env/core/crypto"
	cimpl "github.com/reshifr/secure-env/core/crypto/impl"
	"github.com/stretchr/testify/assert"
)

func Test_ChaChaPolyAE_Open(t *testing.T) {
	t.Parallel()
	t.Run("The same plaintext yields the same buf len", func(t *testing.T) {
		t.Parallel()
		fnRNG := c.FnCSPRNG{Read: rand.Read}
		rng := cimpl.NewAutoRNG(fnRNG)

		cipher := cimpl.ChaChaPolyAE{}
		plaintext := []byte("Hello, World!")

		rawIV := [cimpl.GlobalIV96Len]byte{}
		rng.Read(rawIV[:])
		iv, _ := cimpl.LoadGlobalIV96(rawIV[:])
		baseKey, _ := rng.Block(cimpl.ChaChaPolyAEKeyLen)
		baseBuf, _ := cipher.Seal(iv, baseKey, plaintext)

		const executed = 1000
		for i := 0; i < executed; i++ {
			key, _ := rng.Block(cimpl.ChaChaPolyAEKeyLen)
			buf, _ := cipher.Seal(iv, key, plaintext)
			assert.Equal(t, baseBuf.Len(), buf.Len())
		}
	})
}

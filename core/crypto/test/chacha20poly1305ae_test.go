package crypto_test

// import (
// 	"crypto/rand"
// 	"testing"

// 	c "github.com/reshifr/secure-env/core/crypto"
// 	cimpl "github.com/reshifr/secure-env/core/crypto/impl"
// 	"github.com/stretchr/testify/assert"
// )

// func Test_ChaCha20Poly1305AE_Encrypt(t *testing.T) {
// 	t.Parallel()
// 	t.Run("The same plaintext yields the same buf len", func(t *testing.T) {
// 		t.Parallel()
// 		fnRNG := c.FnCSPRNG{Read: rand.Read}
// 		rng := cimpl.NewAutoRNG(fnRNG)

// 		cipher := cimpl.ChaCha20Poly1305AE{}
// 		plaintext := []byte("Hello, World!")

// 		rawIV := [cimpl.IV96Len]byte{}
// 		rng.Read(rawIV[:])

// 		baseIV, _ := cimpl.LoadIV96(rawIV[:])
// 		baseKey, _ := rng.Block(cimpl.ChaCha20Poly1305AEKeyLen)
// 		baseBuf, _ := cipher.Encrypt(baseIV, baseKey, plaintext)

// 		n := 1000
// 		for i := 0; i < n; i++ {
// 			rng.Read(rawIV[:])
// 			iv, _ := cimpl.LoadIV96(rawIV[:])
// 			key, _ := rng.Block(cimpl.ChaCha20Poly1305AEKeyLen)
// 			buf, _ := cipher.Encrypt(iv, key, plaintext)
// 			assert.Equal(t, baseBuf.Len(), buf.Len())
// 		}
// 	})
// }

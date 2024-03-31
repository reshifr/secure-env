package crypto_impl

// import (
// 	"testing"

// 	mock "github.com/reshifr/secure-env/mocks/core/crypt"
// 	"github.com/stretchr/testify/assert"
// )

// func Test_NewChaCha20Poly1305(t *testing.T) {
// 	t.Parallel()
// 	rng := mock.NewCSPRNG(t)
// 	expCipher := &ChaCha20Poly1305[*mock.CSPRNG]{csprng: rng}

// 	cipher := NewChaCha20Poly1305(rng)
// 	assert.Equal(t, expCipher, cipher)
// }

// func Test_ChaCha20Poly1305_KeyLen(t *testing.T) {
// 	t.Parallel()
// 	rng := mock.NewCSPRNG(t)
// 	cipher := &ChaCha20Poly1305[*mock.CSPRNG]{csprng: rng}
// 	expKeyLen := ChaCha20Poly1305KeyLen

// 	keyLen := cipher.KeyLen()
// 	assert.Equal(t, expKeyLen, keyLen)
// }

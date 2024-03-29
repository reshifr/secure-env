package crypt

// import (
// 	"testing"

// 	crypt_mock "github.com/reshifr/secure-env/mocks/core/crypt"
// 	"github.com/stretchr/testify/assert"
// )

// func Test_NewChacha20Poly1305(t *testing.T) {
// 	t.Parallel()
// 	kdf := crypt_mock.NewKDF(t)
// 	csprng := crypt_mock.NewCSPRNG(t)
// 	expCipher := &Chacha20Poly1305[*crypt_mock.KDF, *crypt_mock.CSPRNG]{
// 		kdf:    kdf,
// 		csprng: csprng,
// 	}

// 	cipher := NewChacha20Poly1305(kdf, csprng)
// 	assert.Equal(t, expCipher, cipher)
// }

// func Test_Chacha20Poly1305_Any(t *testing.T) {
// 	// passphrase := "Renol"
// 	// iv := MakeIV96(0x01020304)
// 	// plaintext := []byte("Hello")
// 	// kdf := &Argon2{}
// 	// csprng := crypt_mock.NewCSPRNG(t)

// 	// cipher := NewChacha20Poly1305(kdf, csprng)
// 	// ciphertext, _ := cipher.Encrypt(passphrase, iv, plaintext)
// 	// t.Log(ciphertext)
// }

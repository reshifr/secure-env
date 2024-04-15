package crypto_impl

import (
	"bytes"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	cmock "github.com/reshifr/secure-env/core/crypto/mock"
	"github.com/stretchr/testify/assert"
)

func Test_MakeRoleSecret(t *testing.T) {
	t.Parallel()
	kdf := cmock.NewKDF(t)

	const keyLen = 16
	cipher := cmock.NewCipher(t)
	cipher.EXPECT().KeyLen().Return(keyLen).Twice()

	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		var key []byte = nil
		const expErr = crypto.ErrReadEntropyFailed
		rng := cmock.NewCSPRNG(t)
		rng.EXPECT().Block(int(keyLen)).Return(key, expErr).Once()

		var expSecret *RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher] = nil

		secret, err := MakeRoleSecret(kdf, rng, cipher)
		assert.Equal(t, secret, expSecret)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		key := bytes.Repeat([]byte{0xff}, keyLen)
		rng := cmock.NewCSPRNG(t)
		rng.EXPECT().Block(int(keyLen)).Return(key, nil).Once()

		expSecret := &RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher]{
			kdf:     kdf,
			rng:     rng,
			cipher:  cipher,
			mainKey: key,
		}

		secret, err := MakeRoleSecret(kdf, rng, cipher)
		assert.True(t, secret.sharedKeys.Empty())
		secret.sharedKeys = nil
		assert.Equal(t, expSecret, secret)
		assert.ErrorIs(t, err, nil)
	})
}

// func Test_LoadRoleSecret(t *testing.T) {
// 	t.Parallel()
// 	kdf := cmock.NewKDF(t)
// 	rng := cmock.NewCSPRNG(t)

// 	t.Run("ErrInvalidSecretId error", func(t *testing.T) {
// 		t.Parallel()
// 		cipher := cmock.NewCipher(t)

// 		id := -1
// 		expErr := crypto.ErrInvalidSecretId
// 		var expSecret *RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher] = nil

// 		secret, err := LoadRoleSecret(kdf, rng, cipher, nil, id, "")
// 		assert.Equal(t, expSecret, secret)
// 		assert.Equal(t, expErr, err)
// 	})

// 	id := 7
// 	ivLen := uint32(8)
// 	cipher := cmock.NewCipher(t)
// 	cipher.EXPECT().IVLen().Return(ivLen).Twice()

// 	t.Run("Main block len ErrInvalidBufferLayout error", func(t *testing.T) {
// 		t.Parallel()
// 		raw := bytes.Repeat([]byte{0xff}, 8)
// 		expErr := crypto.ErrInvalidBufferLayout
// 		var expSecret *RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher] = nil

// 		secret, err := LoadRoleSecret(kdf, rng, cipher, raw, id, "")
// 		assert.Equal(t, expSecret, secret)
// 		assert.Equal(t, expErr, err)
// 	})
// 	t.Run("Shared block len ErrInvalidBufferLayout error", func(t *testing.T) {
// 		t.Parallel()
// 		bitmap := uint64(0x0000000000000001)
// 		bufLen := uint64(64)
// 		rawIV := bytes.Repeat([]byte{0xff}, int(ivLen))
// 		sharedBlock := bytes.Repeat([]byte{0xff}, 8)
// 		raw := append(binary.BigEndian.AppendUint64(nil, bitmap),
// 			binary.BigEndian.AppendUint64(nil, bufLen)...)
// 		raw = append(raw, rawIV...)
// 		raw = append(raw, sharedBlock...)

// 		expErr := crypto.ErrInvalidBufferLayout
// 		var expSecret *RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher] = nil

// 		secret, err := LoadRoleSecret(kdf, rng, cipher, raw, id, "")
// 		assert.Equal(t, expSecret, secret)
// 		assert.Equal(t, expErr, err)
// 	})

// 	t.Run("", func(t *testing.T) {

// 	})
// }

func Test_RoleSecret_Add(t *testing.T) {
	t.Parallel()
	iv := cmock.NewCipherIV(t)
	const keyLen = 16
	const expId = -1

	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		// MakeRoleSecret()
		kdf := cmock.NewKDF(t)

		cipher := cmock.NewCipher(t)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()

		key := bytes.Repeat([]byte{0xff}, keyLen)
		rng := cmock.NewCSPRNG(t)
		rng.EXPECT().Block(int(keyLen)).Return(key, nil).Once()

		// RoleSecret.Add()
		const expErr = crypto.ErrReadEntropyFailed
		rng.EXPECT().Block(RoleSecretSaltLen).Return(nil, expErr).Once()

		secret, _ := MakeRoleSecret(kdf, rng, cipher)
		id, err := secret.Add(iv, "")
		assert.Equal(t, expId, id)
		assert.ErrorIs(t, err, expErr)
	})

	// MakeRoleSecret()
	mainKey := bytes.Repeat([]byte{0xff}, keyLen)
	rng := cmock.NewCSPRNG(t)
	rng.EXPECT().Block(int(keyLen)).Return(mainKey, nil).Times(2)

	// RoleSecret.Add()
	salt := bytes.Repeat([]byte{0xff}, RoleSecretSaltLen)
	rng.EXPECT().Block(RoleSecretSaltLen).Return(salt, nil).Times(65)

	const passphrase = "Ti2Kiujy+AFWjrgz"
	key := bytes.Repeat([]byte{0xff}, keyLen)
	kdf := cmock.NewKDF(t)
	kdf.EXPECT().Key(passphrase, salt, uint32(keyLen)).Return(key).Times(65)

	t.Run("ErrInvalidIVLen error", func(t *testing.T) {
		t.Parallel()
		// MakeRoleSecret()
		cipher := cmock.NewCipher(t)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()

		// RoleSecret.Add()
		cipher.EXPECT().KeyLen().Return(keyLen).Once()

		const expErr = crypto.ErrInvalidIVLen
		cipher.EXPECT().Seal(iv, key, mainKey).Return(nil, expErr).Once()

		secret, _ := MakeRoleSecret(kdf, rng, cipher)
		id, err := secret.Add(iv, passphrase)
		assert.Equal(t, expId, id)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed => ErrInvalidIVLen error", func(t *testing.T) {
		t.Parallel()
		// MakeRoleSecret()
		cipher := cmock.NewCipher(t)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()

		// RoleSecret.Add()
		cipher.EXPECT().KeyLen().Return(keyLen).Times(64)

		buf := cmock.NewCipherBuf(t)
		cipher.EXPECT().Seal(iv, key, mainKey).Return(buf, nil).Times(64)

		// Succeed
		secret, _ := MakeRoleSecret(kdf, rng, cipher)
		for expId := 0; expId < 64; expId++ {
			id, err := secret.Add(iv, passphrase)
			assert.Equal(t, expId, id)
			assert.ErrorIs(t, err, nil)
		}

		// ErrInvalidIVLen error
		const expErr = crypto.ErrSharingExceedsLimit

		for i := 0; i < 4; i++ {
			id, err := secret.Add(iv, passphrase)
			assert.Equal(t, expId, id)
			assert.ErrorIs(t, err, expErr)
		}
	})
}

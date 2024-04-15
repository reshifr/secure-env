package crypto_impl

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	cmock "github.com/reshifr/secure-env/core/crypto/mock"
	"github.com/stretchr/testify/assert"
)

func Test_MakeRoleSecret(t *testing.T) {
	t.Parallel()
	kdf := cmock.NewKDF(t)

	const keyLen = 16
	cipher := cmock.NewCipherAE(t)
	cipher.EXPECT().KeyLen().Return(keyLen).Twice()

	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		var key []byte = nil
		const expErr = crypto.ErrReadEntropyFailed
		rng := cmock.NewCSPRNG(t)
		rng.EXPECT().Block(int(keyLen)).Return(key, expErr).Once()

		var expSecret *RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.CipherAE] = nil

		secret, err := MakeRoleSecret(kdf, rng, cipher)
		assert.Equal(t, secret, expSecret)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		key := bytes.Repeat([]byte{0xff}, keyLen)
		rng := cmock.NewCSPRNG(t)
		rng.EXPECT().Block(int(keyLen)).Return(key, nil).Once()

		expSecret := &RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.CipherAE]{
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

		cipher := cmock.NewCipherAE(t)
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
		cipher := cmock.NewCipherAE(t)
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
		cipher := cmock.NewCipherAE(t)
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

func Test_RoleSecret_Raw(t *testing.T) {
	t.Parallel()
	t.Run("Empty role", func(t *testing.T) {
		t.Parallel()
		var expRawSecret []byte = nil

		secret := &RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.CipherAE]{}
		rawSecret := secret.Raw()
		assert.Equal(t, expRawSecret, rawSecret)
	})

	const keyLen = 16

	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		// MakeRoleSecret()
		cipher := cmock.NewCipherAE(t)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()

		mainKey := bytes.Repeat([]byte{0x10}, keyLen)
		rng := cmock.NewCSPRNG(t)
		rng.EXPECT().Block(int(keyLen)).Return(mainKey, nil).Once()

		// RoleSecret.Add()
		salts := [][]byte{
			bytes.Repeat([]byte{0x20}, RoleSecretSaltLen),
			bytes.Repeat([]byte{0x21}, RoleSecretSaltLen),
			bytes.Repeat([]byte{0x22}, RoleSecretSaltLen),
		}
		for i := 0; i < 3; i++ {
			rng.EXPECT().Block(RoleSecretSaltLen).Return(salts[i], nil).Once()
		}

		cipher.EXPECT().KeyLen().Return(keyLen).Times(3)

		passphrases := []string{
			"yPYk8GEEH.j42P+?",
			"m~34DP0swddPXJ6k",
			"Js2yYNJsfKM?xK3N",
		}
		keys := [][]byte{
			bytes.Repeat([]byte{0x30}, keyLen),
			bytes.Repeat([]byte{0x31}, keyLen),
			bytes.Repeat([]byte{0x32}, keyLen),
		}
		kdf := cmock.NewKDF(t)
		for i := 0; i < 3; i++ {
			kdf.EXPECT().
				Key(passphrases[i], salts[i], uint32(keyLen)).Return(keys[i]).Once()
		}

		iv := cmock.NewCipherIV(t)
		bufs := []*cmock.CipherBuf{
			cmock.NewCipherBuf(t),
			cmock.NewCipherBuf(t),
			cmock.NewCipherBuf(t),
		}
		for i := 0; i < 3; i++ {
			cipher.EXPECT().Seal(iv, keys[i], mainKey).Return(bufs[i], nil).Once()
		}

		// RoleSecret.Raw()
		const bufLen = 11
		rawBufs := [][]byte{
			bytes.Repeat([]byte{0x40}, bufLen),
			bytes.Repeat([]byte{0x41}, bufLen),
			bytes.Repeat([]byte{0x42}, bufLen),
		}
		bufs[0].EXPECT().Len().Return(bufLen).Once()
		for i := 0; i < 3; i++ {
			bufs[i].EXPECT().Raw().Return(rawBufs[i]).Once()
		}

		bitmap, _ := hex.DecodeString("0000000000000007")
		expRawSecret := []byte{}
		expRawSecret = append(expRawSecret, bitmap...)
		expRawSecret = append(expRawSecret, bufLen)
		for i := 0; i < 3; i++ {
			expRawSecret = append(expRawSecret, salts[i]...)
			expRawSecret = append(expRawSecret, rawBufs[i]...)
		}

		secret, _ := MakeRoleSecret(kdf, rng, cipher)
		for i := 0; i < 3; i++ {
			secret.Add(iv, passphrases[i])
		}
		rawSecret := secret.Raw()
		assert.Equal(t, expRawSecret, rawSecret)
	})
}

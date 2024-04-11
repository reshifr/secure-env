package crypto_impl

import (
	"bytes"
	"testing"

	avl "github.com/emirpasic/gods/v2/trees/avltree"
	"github.com/reshifr/secure-env/core/crypto"
	cmock "github.com/reshifr/secure-env/core/crypto/mock"
	"github.com/stretchr/testify/assert"
)

func Test_MakeRoleSecret(t *testing.T) {
	t.Parallel()
	t.Run("Key ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		kdf := cmock.NewKDF(t)
		rng := cmock.NewCSPRNG(t)
		cipher := cmock.NewCipher(t)

		keyLen := uint32(8)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()
		var key []byte = nil
		expErr := crypto.ErrReadEntropyFailed
		rng.EXPECT().Block(int(keyLen)).Return(key, expErr).Once()
		var expSecret *RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher] = nil

		secret, err := MakeRoleSecret(kdf, rng, cipher)
		assert.Equal(t, secret, expSecret)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("RawIV ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		kdf := cmock.NewKDF(t)
		rng := cmock.NewCSPRNG(t)
		cipher := cmock.NewCipher(t)

		keyLen := uint32(8)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()
		key := bytes.Repeat([]byte{0xff}, int(keyLen))
		rng.EXPECT().Block(int(keyLen)).Return(key, nil).Once()

		rawIVLen := uint32(8)
		cipher.EXPECT().IVLen().Return(rawIVLen)
		expErr := crypto.ErrReadEntropyFailed
		rng.EXPECT().Block(int(rawIVLen)).Return(key, expErr).Once()
		var expSecret *RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher] = nil

		secret, err := MakeRoleSecret(kdf, rng, cipher)
		assert.Equal(t, secret, expSecret)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		kdf := cmock.NewKDF(t)
		rng := cmock.NewCSPRNG(t)
		cipher := cmock.NewCipher(t)

		keyLen := uint32(8)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()
		key := bytes.Repeat([]byte{0xff}, int(keyLen))
		rng.EXPECT().Block(int(keyLen)).Return(key, nil).Once()

		rawIVLen := uint32(8)
		cipher.EXPECT().IVLen().Return(rawIVLen)
		rawIV := bytes.Repeat([]byte{0xff}, int(rawIVLen))
		rng.EXPECT().Block(int(rawIVLen)).Return(rawIV, nil).Once()
		iv := cmock.NewCipherIV(t)
		cipher.EXPECT().LoadIV(rawIV).Return(iv, nil).Once()
		expSecret := &RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher]{
			kdf:        kdf,
			csprng:     rng,
			cipher:     cipher,
			mainIV:     iv,
			mainKey:    key,
			sharedKeys: avl.New[int8, RoleSecretSharedKey](),
		}

		secret, err := MakeRoleSecret(kdf, rng, cipher)
		secret.sharedKeys, expSecret.sharedKeys = nil, nil
		assert.Equal(t, secret, expSecret)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_LoadRoleSecret(t *testing.T) {
	t.Parallel()
	t.Run("Id range ErrInvalidSecretId error", func(t *testing.T) {
		t.Parallel()
		kdf := cmock.NewKDF(t)
		rng := cmock.NewCSPRNG(t)
		cipher := cmock.NewCipher(t)
		id := -1
		expErr := crypto.ErrInvalidSecretId
		var expSecret *RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher] = nil
		secret, err := LoadRoleSecret(kdf, rng, cipher, nil, id, "")
		assert.Equal(t, expSecret, secret)
		assert.Equal(t, expErr, err)
	})
}

// func Test_RoleSecret_Add(t *testing.T) {
// 	t.Parallel()
// 	t.Run("ErrSharingExceedsLimit error", func(t *testing.T) {
// 		t.Parallel()
// 		kdf := cmock.NewKDF(t)
// 		rng := cmock.NewCSPRNG(t)
// 		cipher := cmock.NewCipher(t)
// 		passphrase := "0tSYQ87UUmsmYPYcUdefmSpS18EX@_8k"

// 		keyLen := uint32(8)
// 		cipher.EXPECT().KeyLen().Return(keyLen).Once()
// 		key := bytes.Repeat([]byte{0xff}, int(keyLen))
// 		rng.EXPECT().Block(int(keyLen)).Return(key, nil).Once()

// 		rawIVLen := uint32(8)
// 		cipher.EXPECT().IVLen().Return(rawIVLen)
// 		rawIV := bytes.Repeat([]byte{0xff}, int(rawIVLen))
// 		rng.EXPECT().Block(int(rawIVLen)).Return(rawIV, nil).Once()
// 		iv := cmock.NewCipherIV(t)
// 		cipher.EXPECT().LoadIV(rawIV).Return(iv, nil).Once()

// 		salt := [RoleSecretSaltLen]byte{}
// 		rng.EXPECT().Read(salt[:]).Return(nil).Times(64)
// 		userKey := bytes.Repeat([]byte{0xff}, int(keyLen))
// 		cipher.EXPECT().KeyLen().Return(keyLen).Times(64)
// 		kdf.EXPECT().Key(passphrase, salt[:], keyLen).Return(userKey).Times(64)

// 		userIV := cmock.NewCipherIV(t)
// 		buf := cmock.NewCipherBuf(t)
// 		cipher.EXPECT().Encrypt(userIV, userKey, key).Return(buf, nil).Times(64)
// 		expId := -1
// 		expErr := crypto.ErrSharingExceedsLimit
// 		secret, _ := MakeRoleSecret(kdf, rng, cipher)
// 		for i := 0; i < 64; i++ {
// 			secret.Add(userIV, passphrase)
// 		}
// 		for i := 0; i < 8; i++ {
// 			id, err := secret.Add(userIV, passphrase)
// 			assert.Equal(t, expId, id)
// 			assert.ErrorIs(t, err, expErr)
// 		}
// 	})
// 	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
// 		t.Parallel()
// 		kdf := cmock.NewKDF(t)
// 		rng := cmock.NewCSPRNG(t)
// 		cipher := cmock.NewCipher(t)
// 		passphrase := "Z0GtjpPEEcINolbGE.aeNaje8xJIqsPg"

// 		keyLen := uint32(8)
// 		cipher.EXPECT().KeyLen().Return(keyLen).Once()
// 		key := bytes.Repeat([]byte{0xff}, int(keyLen))
// 		rng.EXPECT().Block(int(keyLen)).Return(key, nil).Once()

// 		rawIVLen := uint32(8)
// 		cipher.EXPECT().IVLen().Return(rawIVLen)
// 		rawIV := bytes.Repeat([]byte{0xff}, int(rawIVLen))
// 		rng.EXPECT().Block(int(rawIVLen)).Return(rawIV, nil).Once()
// 		iv := cmock.NewCipherIV(t)
// 		cipher.EXPECT().LoadIV(rawIV).Return(iv, nil).Once()

// 		salt := [RoleSecretSaltLen]byte{}
// 		expErr := crypto.ErrReadEntropyFailed
// 		rng.EXPECT().Read(salt[:]).Return(expErr).Once()
// 		userIV := cmock.NewCipherIV(t)
// 		expId := -1

// 		secret, _ := MakeRoleSecret(kdf, rng, cipher)
// 		id, err := secret.Add(userIV, passphrase)
// 		assert.Equal(t, expId, id)
// 		assert.ErrorIs(t, err, expErr)
// 	})
// 	t.Run("ErrCipherAuthFailed error", func(t *testing.T) {
// 		t.Parallel()
// 		kdf := cmock.NewKDF(t)
// 		rng := cmock.NewCSPRNG(t)
// 		cipher := cmock.NewCipher(t)
// 		passphrase := "5YRCk/hyU=dI2aT6ED8zB#hA57V@2wf,"

// 		keyLen := uint32(8)
// 		cipher.EXPECT().KeyLen().Return(keyLen).Once()
// 		key := bytes.Repeat([]byte{0xff}, int(keyLen))
// 		rng.EXPECT().Block(int(keyLen)).Return(key, nil).Once()

// 		rawIVLen := uint32(8)
// 		cipher.EXPECT().IVLen().Return(rawIVLen)
// 		rawIV := bytes.Repeat([]byte{0xff}, int(rawIVLen))
// 		rng.EXPECT().Block(int(rawIVLen)).Return(rawIV, nil).Once()
// 		iv := cmock.NewCipherIV(t)
// 		cipher.EXPECT().LoadIV(rawIV).Return(iv, nil).Once()

// 		salt := [RoleSecretSaltLen]byte{}
// 		rng.EXPECT().Read(salt[:]).Return(nil).Once()
// 		userKey := bytes.Repeat([]byte{0xff}, int(keyLen))
// 		cipher.EXPECT().KeyLen().Return(keyLen).Once()
// 		kdf.EXPECT().Key(passphrase, salt[:], keyLen).Return(userKey).Once()

// 		userIV := cmock.NewCipherIV(t)
// 		buf := cmock.NewCipherBuf(t)
// 		expErr := crypto.ErrCipherAuthFailed
// 		cipher.EXPECT().Encrypt(userIV, userKey, key).Return(buf, expErr).Once()
// 		expId := -1

// 		secret, _ := MakeRoleSecret(kdf, rng, cipher)
// 		id, err := secret.Add(userIV, passphrase)
// 		assert.Equal(t, expId, id)
// 		assert.ErrorIs(t, err, expErr)
// 	})
// 	t.Run("Succeed", func(t *testing.T) {
// 		t.Parallel()
// 		kdf := cmock.NewKDF(t)
// 		rng := cmock.NewCSPRNG(t)
// 		cipher := cmock.NewCipher(t)
// 		passphrase := "KkQh+2AMK~3#Ka.gcawsjFx=tcN?xUuX"

// 		keyLen := uint32(8)
// 		cipher.EXPECT().KeyLen().Return(keyLen).Once()
// 		key := bytes.Repeat([]byte{0xff}, int(keyLen))
// 		rng.EXPECT().Block(int(keyLen)).Return(key, nil).Once()

// 		rawIVLen := uint32(8)
// 		cipher.EXPECT().IVLen().Return(rawIVLen)
// 		rawIV := bytes.Repeat([]byte{0xff}, int(rawIVLen))
// 		rng.EXPECT().Block(int(rawIVLen)).Return(rawIV, nil).Once()
// 		iv := cmock.NewCipherIV(t)
// 		cipher.EXPECT().LoadIV(rawIV).Return(iv, nil).Once()

// 		salt := [RoleSecretSaltLen]byte{}
// 		rng.EXPECT().Read(salt[:]).Return(nil).Times(64)
// 		userKey := bytes.Repeat([]byte{0xff}, int(keyLen))
// 		cipher.EXPECT().KeyLen().Return(keyLen).Times(64)
// 		kdf.EXPECT().Key(passphrase, salt[:], keyLen).Return(userKey).Times(64)

// 		userIV := cmock.NewCipherIV(t)
// 		buf := cmock.NewCipherBuf(t)
// 		cipher.EXPECT().Encrypt(userIV, userKey, key).Return(buf, nil).Times(64)
// 		secret, _ := MakeRoleSecret(kdf, rng, cipher)
// 		for expId := 0; expId < 64; expId++ {
// 			id, err := secret.Add(userIV, passphrase)
// 			assert.Equal(t, expId, id)
// 			assert.ErrorIs(t, err, nil)
// 		}
// 	})
// }

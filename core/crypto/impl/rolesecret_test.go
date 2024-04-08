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
	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		kdf := cmock.NewKDF(t)
		rng := cmock.NewCSPRNG(t)
		cipher := cmock.NewCipher(t)
		roleIV := cmock.NewCipherIV(t)

		keyLen := uint32(8)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()
		var key []byte = nil
		expErr := crypto.ErrReadEntropyFailed
		rng.EXPECT().Block(int(keyLen)).Return(key, expErr).Once()
		var expSec *RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher] = nil

		sec, err := MakeRoleSecret(kdf, rng, cipher, roleIV)
		assert.Equal(t, sec, expSec)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		kdf := cmock.NewKDF(t)
		rng := cmock.NewCSPRNG(t)
		cipher := cmock.NewCipher(t)
		roleIV := cmock.NewCipherIV(t)

		keyLen := uint32(8)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()
		key := bytes.Repeat([]byte{0xff}, int(keyLen))
		rng.EXPECT().Block(int(keyLen)).Return(key, nil).Once()
		expSec := &RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher]{
			kdf:      kdf,
			csprng:   rng,
			cipher:   cipher,
			iv:       roleIV,
			key:      key,
			userKeys: make(map[int8]roleSecretUserKey),
		}
		sec, err := MakeRoleSecret(kdf, rng, cipher, roleIV)
		assert.Equal(t, sec, expSec)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_RoleSecret_Add(t *testing.T) {
	t.Parallel()
	t.Run("ErrSharingExceedsLimit error", func(t *testing.T) {
		t.Parallel()
		kdf := cmock.NewKDF(t)
		rng := cmock.NewCSPRNG(t)
		cipher := cmock.NewCipher(t)
		roleIV := cmock.NewCipherIV(t)
		passphrase := "0tSYQ87UUmsmYPYcUdefmSpS18EX@_8k"

		keyLen := uint32(8)
		key := bytes.Repeat([]byte{0xff}, int(keyLen))
		cipher.EXPECT().KeyLen().Return(keyLen).Once()
		rng.EXPECT().Block(int(keyLen)).Return(key, nil).Once()

		salt := [RoleSecretSaltLen]byte{}
		rng.EXPECT().Read(salt[:]).Return(nil).Times(64)
		userKey := bytes.Repeat([]byte{0xff}, int(keyLen))
		cipher.EXPECT().KeyLen().Return(keyLen).Times(64)
		kdf.EXPECT().Key(passphrase, salt[:], keyLen).Return(userKey).Times(64)

		userIV := cmock.NewCipherIV(t)
		buf := cmock.NewCipherBuf(t)
		cipher.EXPECT().Seal(userIV, userKey, key).Return(buf, nil).Times(64)
		expId := int8(-1)
		expErr := crypto.ErrSharingExceedsLimit

		var id int8
		var err error
		sec, _ := MakeRoleSecret(kdf, rng, cipher, roleIV)
		for i := 0; i < 64; i++ {
			sec.Add(userIV, passphrase)
		}
		for i := 0; i < 8; i++ {
			id, err = sec.Add(userIV, passphrase)
			assert.Equal(t, expId, id)
			assert.ErrorIs(t, err, expErr)
		}
	})
	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		kdf := cmock.NewKDF(t)
		rng := cmock.NewCSPRNG(t)
		cipher := cmock.NewCipher(t)
		roleIV := cmock.NewCipherIV(t)
		passphrase := "Z0GtjpPEEcINolbGE.aeNaje8xJIqsPg"

		keyLen := uint32(8)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()
		key := bytes.Repeat([]byte{0xff}, int(keyLen))
		rng.EXPECT().Block(int(keyLen)).Return(key, nil).Once()

		salt := [RoleSecretSaltLen]byte{}
		expErr := crypto.ErrReadEntropyFailed
		rng.EXPECT().Read(salt[:]).Return(expErr).Once()
		userIV := cmock.NewCipherIV(t)
		expId := int8(-1)

		sec, _ := MakeRoleSecret(kdf, rng, cipher, roleIV)
		id, err := sec.Add(userIV, passphrase)
		assert.Equal(t, expId, id)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("ErrCipherAuthFailed error", func(t *testing.T) {
		t.Parallel()
		kdf := cmock.NewKDF(t)
		rng := cmock.NewCSPRNG(t)
		cipher := cmock.NewCipher(t)
		roleIV := cmock.NewCipherIV(t)
		passphrase := "5YRCk/hyU=dI2aT6ED8zB#hA57V@2wf,"

		keyLen := uint32(8)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()
		key := bytes.Repeat([]byte{0xff}, int(keyLen))
		rng.EXPECT().Block(int(keyLen)).Return(key, nil).Once()

		salt := [RoleSecretSaltLen]byte{}
		rng.EXPECT().Read(salt[:]).Return(nil).Once()
		userKey := bytes.Repeat([]byte{0xff}, int(keyLen))
		cipher.EXPECT().KeyLen().Return(keyLen).Once()
		kdf.EXPECT().Key(passphrase, salt[:], keyLen).Return(userKey).Once()

		userIV := cmock.NewCipherIV(t)
		buf := cmock.NewCipherBuf(t)
		expErr := crypto.ErrCipherAuthFailed
		cipher.EXPECT().Seal(userIV, userKey, key).Return(buf, expErr).Once()
		expId := int8(-1)

		sec, _ := MakeRoleSecret(kdf, rng, cipher, roleIV)
		id, err := sec.Add(userIV, passphrase)
		assert.Equal(t, expId, id)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		kdf := cmock.NewKDF(t)
		rng := cmock.NewCSPRNG(t)
		cipher := cmock.NewCipher(t)
		roleIV := cmock.NewCipherIV(t)
		passphrase := "KkQh+2AMK~3#Ka.gcawsjFx=tcN?xUuX"

		keyLen := uint32(8)
		key := bytes.Repeat([]byte{0xff}, int(keyLen))
		cipher.EXPECT().KeyLen().Return(keyLen).Once()
		rng.EXPECT().Block(int(keyLen)).Return(key, nil).Once()

		salt := [RoleSecretSaltLen]byte{}
		rng.EXPECT().Read(salt[:]).Return(nil).Times(64)
		userKey := bytes.Repeat([]byte{0xff}, int(keyLen))
		cipher.EXPECT().KeyLen().Return(keyLen).Times(64)
		kdf.EXPECT().Key(passphrase, salt[:], keyLen).Return(userKey).Times(64)

		userIV := cmock.NewCipherIV(t)
		buf := cmock.NewCipherBuf(t)
		cipher.EXPECT().Seal(userIV, userKey, key).Return(buf, nil).Times(64)

		var id int8
		var err error
		sec, _ := MakeRoleSecret(kdf, rng, cipher, roleIV)
		for i := 0; i < 64; i++ {
			expId := int8(64 - i - 1)
			id, err = sec.Add(userIV, passphrase)
			assert.Equal(t, expId, id)
			assert.ErrorIs(t, err, nil)
		}
	})
}

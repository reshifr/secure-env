package crypto_impl

import (
	"bytes"
	"encoding/binary"
	"testing"

	avl "github.com/emirpasic/gods/v2/trees/avltree"
	"github.com/reshifr/secure-env/core/crypto"
	cmock "github.com/reshifr/secure-env/core/crypto/mock"
	"github.com/stretchr/testify/assert"
)

func Test_MakeRoleSecret(t *testing.T) {
	t.Parallel()
	kdf := cmock.NewKDF(t)
	iv := cmock.NewCipherIV(t)

	passphrase := "U~mKIO5/P5oZ&VY&l,Sdwo@Qp,sjLoo2"
	keyLen := uint32(16)
	ivLen := uint32(8)

	t.Run("Generate key ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		cipher := cmock.NewCipher(t)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()

		var key []byte = nil
		expErr := crypto.ErrReadEntropyFailed
		rng := cmock.NewCSPRNG(t)
		rng.EXPECT().Block(int(keyLen)).Return(key, expErr).Once()

		var expSecret *RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher] = nil
		expId := -1

		secret, id, err := MakeRoleSecret(kdf, rng, cipher, iv, passphrase)
		assert.Equal(t, secret, expSecret)
		assert.Equal(t, expId, id)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Generate raw iv ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		cipher := cmock.NewCipher(t)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()

		key := bytes.Repeat([]byte{0xff}, int(keyLen))
		rng := cmock.NewCSPRNG(t)
		rng.EXPECT().Block(int(keyLen)).Return(key, nil).Once()

		cipher.EXPECT().IVLen().Return(ivLen)

		expErr := crypto.ErrReadEntropyFailed
		rng.EXPECT().Block(int(ivLen)).Return(key, expErr).Once()

		var expSecret *RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher] = nil
		expId := -1

		secret, id, err := MakeRoleSecret(kdf, rng, cipher, iv, passphrase)
		assert.Equal(t, secret, expSecret)
		assert.Equal(t, expId, id)
		assert.ErrorIs(t, err, expErr)
	})

	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		cipher := cmock.NewCipher(t)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()

		mainKey := bytes.Repeat([]byte{0xff}, int(keyLen))
		rng := cmock.NewCSPRNG(t)
		rng.EXPECT().Block(int(keyLen)).Return(mainKey, nil).Once()

		cipher.EXPECT().IVLen().Return(ivLen)

		rawIV := bytes.Repeat([]byte{0xff}, int(ivLen))
		rng.EXPECT().Block(int(ivLen)).Return(rawIV, nil).Once()

		cipher.EXPECT().LoadIV(rawIV).Return(iv, nil).Once()

		// Add()
		salt := bytes.Repeat([]byte{0xff}, RoleSecretSaltLen)
		rng.EXPECT().Block(RoleSecretSaltLen).Return(salt, nil).Once()

		cipher.EXPECT().KeyLen().Return(keyLen).Once()

		key := bytes.Repeat([]byte{0xff}, int(keyLen))
		kdf := cmock.NewKDF(t)
		kdf.EXPECT().Key(passphrase, salt, keyLen).Return(key).Once()

		buf := cmock.NewCipherBuf(t)
		cipher.EXPECT().Encrypt(iv, key, mainKey).Return(buf, nil).Once()

		bitmap := uint64(0x0000000000000001)

		expId := 0
		expSharedKey := RoleSecretSharedKey{salt: salt, buf: buf}
		expSharedKeys := avl.New[int, RoleSecretSharedKey]()
		expSharedKeys.Put(expId, expSharedKey)
		expSecret := &RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher]{
			kdf:     kdf,
			csprng:  rng,
			cipher:  cipher,
			bitmap:  bitmap,
			mainIV:  iv,
			mainKey: key,
		}

		secret, id, err := MakeRoleSecret(kdf, rng, cipher, iv, passphrase)
		assert.Equal(t, expSharedKeys.Keys(), secret.sharedKeys.Keys())
		assert.Equal(t, expSharedKeys.Values(), secret.sharedKeys.Values())
		secret.sharedKeys = nil
		assert.Equal(t, expSecret, secret)
		assert.Equal(t, expId, id)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_LoadRoleSecret(t *testing.T) {
	t.Parallel()
	kdf := cmock.NewKDF(t)
	rng := cmock.NewCSPRNG(t)

	t.Run("ErrInvalidSecretId error", func(t *testing.T) {
		t.Parallel()
		cipher := cmock.NewCipher(t)

		id := -1
		expErr := crypto.ErrInvalidSecretId
		var expSecret *RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher] = nil

		secret, err := LoadRoleSecret(kdf, rng, cipher, nil, id, "")
		assert.Equal(t, expSecret, secret)
		assert.Equal(t, expErr, err)
	})

	id := 7
	ivLen := uint32(8)
	cipher := cmock.NewCipher(t)
	cipher.EXPECT().IVLen().Return(ivLen).Twice()

	t.Run("Main block len ErrInvalidBufferLayout error", func(t *testing.T) {
		t.Parallel()
		raw := bytes.Repeat([]byte{0xff}, 8)
		expErr := crypto.ErrInvalidBufferLayout
		var expSecret *RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher] = nil

		secret, err := LoadRoleSecret(kdf, rng, cipher, raw, id, "")
		assert.Equal(t, expSecret, secret)
		assert.Equal(t, expErr, err)
	})
	t.Run("Shared block len ErrInvalidBufferLayout error", func(t *testing.T) {
		t.Parallel()
		bitmap := uint64(0x0000000000000001)
		bufLen := uint64(64)
		rawIV := bytes.Repeat([]byte{0xff}, int(ivLen))
		sharedBlock := bytes.Repeat([]byte{0xff}, 8)
		raw := append(binary.BigEndian.AppendUint64(nil, bitmap),
			binary.BigEndian.AppendUint64(nil, bufLen)...)
		raw = append(raw, rawIV...)
		raw = append(raw, sharedBlock...)

		expErr := crypto.ErrInvalidBufferLayout
		var expSecret *RoleSecret[*cmock.KDF, *cmock.CSPRNG, *cmock.Cipher] = nil

		secret, err := LoadRoleSecret(kdf, rng, cipher, raw, id, "")
		assert.Equal(t, expSecret, secret)
		assert.Equal(t, expErr, err)
	})

	t.Run("", func(t *testing.T) {
		
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

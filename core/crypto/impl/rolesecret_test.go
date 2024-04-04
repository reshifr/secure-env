package crypto_impl

import (
	"bytes"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	mock "github.com/reshifr/secure-env/core/crypto/mock"
	"github.com/stretchr/testify/assert"
)

// func Test_Main(t *testing.T) {
// 	kdf := Argon2{}
// 	fnRNG := crypto.FnCSPRNG{Read: rand.Read}
// 	rng := NewAutoRNG(fnRNG)
// 	cipher := NewChaCha20Poly1305(rng)

// 	roleIV, _ := MakeIV96(bytes.Repeat([]byte{0x11}, IV96FixedLen))
// 	sec, _ := MakeRoleSecret(kdf, rng, cipher, roleIV)

// 	userIV, _ := MakeIV96(bytes.Repeat([]byte{0x22}, IV96FixedLen))
// 	for i := 0; i < 100; i++ {
// 		sec.Add(userIV, "Renol")
// 		// id, _ := sec.Add(userIV, "Renol")
// 		// t.Logf("Id: %v\n", id)
// 	}

// 	for i := 0; i < 63; i++ {
// 		sec.Del(int8(i))
// 	}

// 	for i := 0; i < 2; i++ {
// 		sec.Add(userIV, "Renol")
// 		// id, _ := sec.Add(userIV, "Renol")
// 		// t.Logf("Id: %v\n", id)
// 	}

// 	t.Logf("Bitmap: %072b\n", sec.bitmap)
// 	t.Logf("ObjIV: %x\n", sec.iv.Raw())
// 	t.Logf("SharedKey: %x\n", sec.key)
// 	for id, val := range sec.userKeys {
// 		t.Logf("EncrKeys[%02v][  IV]: %x\n", id, val.buf.RawIV())
// 		t.Logf("EncrKeys[%02v][ Add]: %x\n", id, val.buf.Add())
// 		t.Logf("EncrKeys[%02v][Salt]: %x\n", id, val.salt)
// 	}
// 	t.Logf("EncrKeysLen: %v\n", len(sec.userKeys))
// }

func Test_MakeRoleSecret(t *testing.T) {
	t.Parallel()
	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		kdf := mock.NewKDF(t)
		rng := mock.NewCSPRNG(t)
		cipher := mock.NewCipher(t)
		roleIV := mock.NewCipherIV(t)

		keyLen := uint32(8)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()
		var key []byte = nil
		expErr := crypto.ErrReadEntropyFailed
		rng.EXPECT().Make(int(keyLen)).Return(key, expErr).Once()
		var expSec *RoleSecret[*mock.KDF, *mock.CSPRNG, *mock.Cipher] = nil

		sec, err := MakeRoleSecret(kdf, rng, cipher, roleIV)
		assert.Equal(t, sec, expSec)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		kdf := mock.NewKDF(t)
		rng := mock.NewCSPRNG(t)
		cipher := mock.NewCipher(t)
		roleIV := mock.NewCipherIV(t)

		keyLen := uint32(8)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()
		key := bytes.Repeat([]byte{0xff}, int(keyLen))
		rng.EXPECT().Make(int(keyLen)).Return(key, nil).Once()
		expSec := &RoleSecret[*mock.KDF, *mock.CSPRNG, *mock.Cipher]{
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
		kdf := mock.NewKDF(t)
		rng := mock.NewCSPRNG(t)
		cipher := mock.NewCipher(t)
		roleIV := mock.NewCipherIV(t)
		passphrase := "0tSYQ87UUmsmYPYcUdefmSpS18EX@_8k"

		keyLen := uint32(8)
		cipher.EXPECT().KeyLen().Return(keyLen).Times(65)
		key := bytes.Repeat([]byte{0xff}, int(keyLen))
		rng.EXPECT().Make(int(keyLen)).Return(key, nil).Once()

		salt := [RoleSecretSaltLen]byte{}
		rng.EXPECT().Read(salt[:]).Return(nil).Times(64)
		userKey := bytes.Repeat([]byte{0xff}, int(keyLen))
		kdf.EXPECT().Key(passphrase, salt[:], keyLen).Return(userKey).Times(64)

		userIV := mock.NewCipherIV(t)
		buf := mock.NewCipherBuf(t)
		cipher.EXPECT().Seal(userIV, userKey, key).Return(buf, nil).Times(64)
		expId := int8(-1)
		expErr := crypto.ErrSharingExceedsLimit

		var id int8
		var err error
		sec, _ := MakeRoleSecret(kdf, rng, cipher, roleIV)
		for i := 0; i < 72; i++ {
			id, err = sec.Add(userIV, passphrase)
		}
		assert.Equal(t, expId, id)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		kdf := mock.NewKDF(t)
		rng := mock.NewCSPRNG(t)
		cipher := mock.NewCipher(t)
		roleIV := mock.NewCipherIV(t)
		passphrase := "0tSYQ87UUmsmYPYcUdefmSpS18EX@_8k"

		keyLen := uint32(8)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()
		key := bytes.Repeat([]byte{0xff}, int(keyLen))
		rng.EXPECT().Make(int(keyLen)).Return(key, nil).Once()

		salt := [RoleSecretSaltLen]byte{}
		expErr := crypto.ErrReadEntropyFailed
		rng.EXPECT().Read(salt[:]).Return(expErr).Once()
		userIV := mock.NewCipherIV(t)
		expId := int8(-1)

		sec, _ := MakeRoleSecret(kdf, rng, cipher, roleIV)
		id, err := sec.Add(userIV, passphrase)
		assert.Equal(t, expId, id)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("ErrCipherAuthFailed error", func(t *testing.T) {
		t.Parallel()
		kdf := mock.NewKDF(t)
		rng := mock.NewCSPRNG(t)
		cipher := mock.NewCipher(t)
		roleIV := mock.NewCipherIV(t)
		passphrase := "0tSYQ87UUmsmYPYcUdefmSpS18EX@_8k"

		keyLen := uint32(8)
		cipher.EXPECT().KeyLen().Return(keyLen).Twice()
		key := bytes.Repeat([]byte{0xff}, int(keyLen))
		rng.EXPECT().Make(int(keyLen)).Return(key, nil).Once()

		salt := [RoleSecretSaltLen]byte{}
		rng.EXPECT().Read(salt[:]).Return(nil).Once()
		userKey := bytes.Repeat([]byte{0xff}, int(keyLen))
		kdf.EXPECT().Key(passphrase, salt[:], keyLen).Return(userKey).Once()

		userIV := mock.NewCipherIV(t)
		buf := mock.NewCipherBuf(t)
		expErr := crypto.ErrCipherAuthFailed
		cipher.EXPECT().Seal(userIV, userKey, key).Return(buf, expErr).Once()
		expId := int8(-1)

		sec, _ := MakeRoleSecret(kdf, rng, cipher, roleIV)
		id, err := sec.Add(userIV, passphrase)
		assert.Equal(t, expId, id)
		assert.ErrorIs(t, err, expErr)
	})
}

package crypto_impl

import (
	"bytes"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	cmock "github.com/reshifr/secure-env/core/crypto/mock"
	"github.com/stretchr/testify/assert"
)

func Test_NewRoleAuthorizer(t *testing.T) {
	t.Parallel()
	kdf := cmock.NewKDF(t)
	rng := cmock.NewRNG(t)
	cipher := cmock.NewAE(t)
	expAuthorizer := RoleAuthorizer[*cmock.KDF, *cmock.RNG, *cmock.AE]{
		kdf:    kdf,
		rng:    rng,
		cipher: cipher,
	}

	authorizer := NewRoleAuthorizer(kdf, rng, cipher)
	assert.Equal(t, expAuthorizer, authorizer)
}

func Test_RoleAuthorizer_Make(t *testing.T) {
	t.Parallel()
	iv := cmock.NewIV(t)
	kdf := cmock.NewKDF(t)
	cipher := cmock.NewAE(t)

	const accessKeyLen = 12
	var expAccessKey []byte = nil
	var expBlock []byte = nil
	const expErr = crypto.ErrReadEntropyFailed

	t.Run("Generate access key ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		var accessKey []byte = nil
		rng := cmock.NewRNG(t)
		rng.EXPECT().Block(int(accessKeyLen)).Return(accessKey, expErr).Once()

		expAccessKey := bytes.Clone(accessKey)

		authorizer := NewRoleAuthorizer(kdf, rng, cipher)
		accessKey, block, err := authorizer.Make(iv, nil, accessKeyLen)
		assert.Equal(t, expAccessKey, accessKey)
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, expErr)
	})

	accessKey := bytes.Repeat([]byte{0x22}, accessKeyLen)
	salt := [RoleAuthorizerSaltLen]byte{}

	t.Run("Generate salt ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		rng := cmock.NewRNG(t)
		rng.EXPECT().Block(int(accessKeyLen)).Return(accessKey, nil).Once()
		rng.EXPECT().Read(salt[:]).Return(expErr).Once()

		authorizer := NewRoleAuthorizer(kdf, rng, cipher)
		accessKey, block, err := authorizer.Make(iv, nil, accessKeyLen)
		assert.Equal(t, expAccessKey, accessKey)
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, expErr)
	})

	const keyLen = 8
	passphrase := []byte("tHGuv,hQjjs?ZA8j")

	t.Run("ErrAuthFailed error", func(t *testing.T) {
		t.Parallel()
		rng := cmock.NewRNG(t)
		rng.EXPECT().Block(int(accessKeyLen)).Return(accessKey, nil).Once()
		rng.EXPECT().Read(salt[:]).Return(nil).Once()

		cipher := cmock.NewAE(t)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()

		var key []byte = nil
		kdf := cmock.NewKDF(t)
		kdf.EXPECT().Key(passphrase, salt[:], uint32(keyLen)).Return(key).Once()

		var buf []byte = nil
		const expErr = crypto.ErrAuthFailed
		cipher.EXPECT().Seal(iv, key, accessKey).Return(buf, expErr).Once()

		authorizer := NewRoleAuthorizer(kdf, rng, cipher)
		accessKey, block, err := authorizer.Make(iv, passphrase, accessKeyLen)
		assert.Equal(t, expAccessKey, accessKey)
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		rng := cmock.NewRNG(t)
		rng.EXPECT().Block(int(accessKeyLen)).Return(accessKey, nil).Once()
		rng.EXPECT().Read(salt[:]).Return(nil).Once()

		cipher := cmock.NewAE(t)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()

		key := bytes.Repeat([]byte{0x11}, keyLen)
		kdf = cmock.NewKDF(t)
		kdf.EXPECT().Key(passphrase, salt[:], uint32(keyLen)).Return(key).Once()

		buf := bytes.Repeat([]byte{0x44}, 10)
		cipher.EXPECT().Seal(iv, key, accessKey).Return(buf, nil).Once()

		expAccessKey := bytes.Clone(accessKey)
		expBlock := append(salt[:], buf...)

		authorizer := NewRoleAuthorizer(kdf, rng, cipher)
		accessKey, block, err := authorizer.Make(iv, passphrase, accessKeyLen)
		assert.Equal(t, expAccessKey, accessKey)
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_RoleAuthorizer_Open(t *testing.T) {
	t.Parallel()
	rng := cmock.NewRNG(t)
	var expAccessKey []byte = nil

	t.Run("ErrInvalidBlockLen error", func(t *testing.T) {
		t.Parallel()
		kdf := cmock.NewKDF(t)
		cipher := cmock.NewAE(t)

		block := bytes.Repeat([]byte{0x55}, 8)
		const expErr = crypto.ErrInvalidBlockLen

		authorizer := NewRoleAuthorizer(kdf, rng, cipher)
		accessKey, err := authorizer.Open(nil, block)
		assert.Equal(t, expAccessKey, accessKey)
		assert.ErrorIs(t, err, expErr)
	})

	const keyLen = 8
	passphrase := []byte("p,GOffHa6TZ4v/s-")
	key := bytes.Repeat([]byte{0x11}, keyLen)

	salt := bytes.Repeat([]byte{0x33}, RoleAuthorizerSaltLen)
	buf := bytes.Repeat([]byte{0x44}, 10)
	kdf := cmock.NewKDF(t)
	kdf.EXPECT().Key(passphrase, salt, uint32(keyLen)).Return(key).Twice()

	t.Run("ErrAuthFailed error", func(t *testing.T) {
		t.Parallel()
		cipher := cmock.NewAE(t)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()

		const expErr = crypto.ErrAuthFailed
		var accessKey []byte = nil
		cipher.EXPECT().Open(key, buf).Return(accessKey, expErr).Once()

		block := append(salt, buf...)

		authorizer := NewRoleAuthorizer(kdf, rng, cipher)
		accessKey, err := authorizer.Open(passphrase, block)
		assert.Equal(t, expAccessKey, accessKey)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		cipher := cmock.NewAE(t)
		cipher.EXPECT().KeyLen().Return(keyLen).Once()

		const accessKeyLen = 12
		accessKey := bytes.Repeat([]byte{0x22}, accessKeyLen)
		cipher.EXPECT().Open(key, buf).Return(accessKey, nil).Once()

		block := append(salt, buf...)
		expAccessKey := bytes.Clone(accessKey)

		authorizer := NewRoleAuthorizer(kdf, rng, cipher)
		accessKey, err := authorizer.Open(passphrase, block)
		assert.Equal(t, expAccessKey, accessKey)
		assert.ErrorIs(t, err, nil)
	})
}

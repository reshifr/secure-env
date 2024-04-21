package crypto_impl

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	cmock "github.com/reshifr/secure-env/core/crypto/mock"
	"github.com/stretchr/testify/assert"
)

func Test_AESGCM_KeyLen(t *testing.T) {
	t.Parallel()
	const expKeyLen = uint32(AESGCMKeyLen)

	cipher := AESGCM{}
	keyLen := cipher.KeyLen()
	assert.Equal(t, expKeyLen, keyLen)
}

func Test_AESGCM_Seal(t *testing.T) {
	t.Parallel()
	cipher := AESGCM{}

	t.Run("ErrInvalidIVLen error", func(t *testing.T) {
		t.Parallel()
		iv := cmock.NewIV(t)
		iv.EXPECT().Len().Return(8).Once()

		var expBuf []byte = nil
		const expErr = crypto.ErrInvalidIVLen

		buf, err := cipher.Seal(iv, nil, nil)
		assert.Equal(t, expBuf, buf)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("ErrInvalidKeyLen error", func(t *testing.T) {
		t.Parallel()
		iv := cmock.NewIV(t)
		iv.EXPECT().Len().Return(AESGCMIVLen).Once()

		key := bytes.Repeat([]byte{0x11}, 8)
		var expBuf []byte = nil
		const expErr = crypto.ErrInvalidKeyLen

		buf, err := cipher.Seal(iv, key, nil)
		assert.Equal(t, expBuf, buf)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		iv := cmock.NewIV(t)
		iv.EXPECT().Len().Return(AESGCMIVLen).Once()

		key, _ := hex.DecodeString(
			"c4fcdf96ba5fb52c72ad024d8b7eaeef" +
				"b63e909b63ed92cf0fbf31fc71c6d704")

		rawIV, _ := hex.DecodeString("111111112222222222222222")
		iv.EXPECT().Invoke().Return(rawIV).Once()

		plaintext := []byte("Hello, World!")
		ciphertext, _ := hex.DecodeString(
			"8c69530d9a7bb89e8660b5b8e1103070" +
				"85ec6cdbb2fc0c6a1cde5e343f")
		expBuf := append(rawIV, ciphertext...)

		buf, err := cipher.Seal(iv, key, plaintext)
		assert.Equal(t, buf, expBuf)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_AESGCM_Open(t *testing.T) {
	t.Parallel()
	cipher := AESGCM{}

	t.Run("ErrInvalidBufLayout error", func(t *testing.T) {
		t.Parallel()
		buf := bytes.Repeat([]byte{0x22}, 8)
		var expPlaintext []byte = nil
		const expErr = crypto.ErrInvalidBufLayout

		plaintext, err := cipher.Open(nil, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("ErrInvalidKeyLen error", func(t *testing.T) {
		t.Parallel()
		key := bytes.Repeat([]byte{0x11}, 8)
		buf := bytes.Repeat([]byte{0x22}, IV96Len)
		var expPlaintext []byte = nil
		const expErr = crypto.ErrInvalidKeyLen

		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})

	rawIV, _ := hex.DecodeString("111111112222222222222222")
	ciphertext, _ := hex.DecodeString(
		"8c69530d9a7bb89e8660b5b8e1103070" +
			"85ec6cdbb2fc0c6a1cde5e343f")
	buf := append(rawIV, ciphertext...)

	t.Run("ErrAuthFailed error", func(t *testing.T) {
		t.Parallel()
		key, _ := hex.DecodeString(
			"27fb29cdfff36b420da50b61dc15380d" +
				"626bc422352488e10a272144186566b8")
		var expPlaintext []byte = nil
		const expErr = crypto.ErrAuthFailed

		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		key, _ := hex.DecodeString(
			"c4fcdf96ba5fb52c72ad024d8b7eaeef" +
				"b63e909b63ed92cf0fbf31fc71c6d704")
		expPlaintext := []byte("Hello, World!")

		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, nil)
	})
}

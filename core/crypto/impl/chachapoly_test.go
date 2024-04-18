package crypto_impl

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	cmock "github.com/reshifr/secure-env/core/crypto/mock"
	"github.com/stretchr/testify/assert"
)

func Test_ChaChaPoly_KeyLen(t *testing.T) {
	t.Parallel()
	const expKeyLen = uint32(ChaChaPolyKeyLen)

	cipher := ChaChaPoly{}
	keyLen := cipher.KeyLen()
	assert.Equal(t, expKeyLen, keyLen)
}

func Test_ChaChaPoly_Seal(t *testing.T) {
	t.Parallel()
	cipher := ChaChaPoly{}

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
		iv.EXPECT().Len().Return(ChaChaPolyIVLen).Once()

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
		iv.EXPECT().Len().Return(ChaChaPolyIVLen).Once()

		key, _ := hex.DecodeString(
			"f1507d5e3f9e2fc69dce797acc3cf95c" +
				"a5636a597c9a07becb81023bae55d00d")

		rawIV, _ := hex.DecodeString("111111112222222222222222")
		iv.EXPECT().Invoke().Return(rawIV).Once()

		plaintext := []byte("Hello, World!")
		ciphertext, _ := hex.DecodeString(
			"60e649ea00241fd69a3df92b82d9729d" +
				"f130ab55c66bdf03b0fcc8b70b")
		expBuf := append(rawIV, ciphertext...)

		buf, err := cipher.Seal(iv, key, plaintext)
		assert.Equal(t, buf, expBuf)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_ChaChaPoly_Open(t *testing.T) {
	t.Parallel()
	cipher := ChaChaPoly{}

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
		"60e649ea00241fd69a3df92b82d9729d" +
			"f130ab55c66bdf03b0fcc8b70b")
	buf := append(rawIV, ciphertext...)

	t.Run("ErrAuthFailed error", func(t *testing.T) {
		t.Parallel()
		key, _ := hex.DecodeString(
			"e4a1869b8db702549b4d0d69d5c0482c" +
				"1a82a2e8fa7191c2ea7aaa2dbd2631b9")
		var expPlaintext []byte = nil
		const expErr = crypto.ErrAuthFailed

		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		key, _ := hex.DecodeString(
			"f1507d5e3f9e2fc69dce797acc3cf95c" +
				"a5636a597c9a07becb81023bae55d00d")
		expPlaintext := []byte("Hello, World!")

		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, nil)
	})
}

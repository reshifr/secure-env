package crypto_impl

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	cmock "github.com/reshifr/secure-env/core/crypto/mock"
	"github.com/stretchr/testify/assert"
)

func Test_ChaChaPolyAE_KeyLen(t *testing.T) {
	t.Parallel()
	cipher := ChaChaPolyAE{}
	const expKeyLen = uint32(ChaChaPolyAEKeyLen)

	keyLen := cipher.KeyLen()
	assert.Equal(t, expKeyLen, keyLen)
}

func Test_ChaChaPolyAE_MakeBuf(t *testing.T) {
	t.Parallel()
	rawIV := make([]byte, ChaChaPolyAEIVLen)
	ciphertext, _ := hex.DecodeString("ce3ff9d23231a582")

	cipher := ChaChaPolyAE{}
	cipher.MakeBuf(rawIV, ciphertext)
}

func Test_ChaChaPolyAE_LoadBuf(t *testing.T) {
	t.Parallel()
	rawBuf, _ := hex.DecodeString("f5bbbc589cf1246cbcd47b61f8109b1804544156")

	cipher := ChaChaPolyAE{}
	cipher.LoadBuf(rawBuf)
}

func Test_ChaChaPolyAE_Seal(t *testing.T) {
	t.Parallel()
	cipher := ChaChaPolyAE{}

	t.Run("ErrInvalidIVLen error", func(t *testing.T) {
		t.Parallel()
		iv := cmock.NewCipherIV(t)
		iv.EXPECT().Len().Return(8).Once()

		var expBuf crypto.CipherBuf = nil
		const expErr = crypto.ErrInvalidIVLen

		buf, err := cipher.Seal(iv, nil, nil)
		assert.Equal(t, expBuf, buf)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("ErrInvalidKeyLen error", func(t *testing.T) {
		t.Parallel()
		iv := cmock.NewCipherIV(t)
		iv.EXPECT().Len().Return(ChaChaPolyAEIVLen).Once()

		key := bytes.Repeat([]byte{0xff}, 8)
		var expBuf crypto.CipherBuf = nil
		const expErr = crypto.ErrInvalidKeyLen

		buf, err := cipher.Seal(iv, key, nil)
		assert.Equal(t, expBuf, buf)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		iv := cmock.NewCipherIV(t)
		iv.EXPECT().Len().Return(ChaChaPolyAEIVLen).Once()

		key, _ := hex.DecodeString(
			"f1507d5e3f9e2fc69dce797acc3cf95c" +
				"a5636a597c9a07becb81023bae55d00d")

		rawIV, _ := hex.DecodeString("111111112222222222222222")
		iv.EXPECT().Invoke().Return(rawIV).Once()

		plaintext := []byte("Hello, World!")
		ciphertext, _ := hex.DecodeString(
			"60e649ea00241fd69a3df92b82d9729d" +
				"f130ab55c66bdf03b0fcc8b70b")
		expBuf, _ := cipher.MakeBuf(rawIV, ciphertext)

		buf, err := cipher.Seal(iv, key, plaintext)
		assert.Equal(t, buf, expBuf)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_ChaChaPolyAE_Open(t *testing.T) {
	t.Parallel()
	cipher := ChaChaPolyAE{}

	t.Run("ErrInvalidIVLen error", func(t *testing.T) {
		t.Parallel()
		buf := cmock.NewCipherBuf(t)
		rawIV := bytes.Repeat([]byte{0xff}, 8)
		buf.EXPECT().RawIV().Return(rawIV).Once()

		var expPlaintext []byte = nil
		const expErr = crypto.ErrInvalidIVLen

		plaintext, err := cipher.Open(nil, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("ErrInvalidKeyLen error", func(t *testing.T) {
		t.Parallel()
		buf := cmock.NewCipherBuf(t)
		rawIV := bytes.Repeat([]byte{0xff}, ChaChaPolyAEIVLen)
		buf.EXPECT().RawIV().Return(rawIV).Once()

		key := bytes.Repeat([]byte{0xff}, 8)
		var expPlaintext []byte = nil
		const expErr = crypto.ErrInvalidKeyLen

		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})

	rawIV, _ := hex.DecodeString("111111112222222222222222")

	t.Run("ErrCipherAuthFailed error", func(t *testing.T) {
		t.Parallel()
		buf := cmock.NewCipherBuf(t)
		buf.EXPECT().RawIV().Return(rawIV).Once()

		key, _ := hex.DecodeString(
			"e4a1869b8db702549b4d0d69d5c0482c" +
				"1a82a2e8fa7191c2ea7aaa2dbd2631b9")

		ciphertext, _ := hex.DecodeString(
			"60e649ea00241fd69a3df92b82d9729d" +
				"f130ab55c66bdf03b0fcc8b70b")
		buf.EXPECT().Ciphertext().Return(ciphertext).Once()

		var expPlaintext []byte = nil
		const expErr = crypto.ErrCipherAuthFailed

		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		buf := cmock.NewCipherBuf(t)
		buf.EXPECT().RawIV().Return(rawIV).Once()

		key, _ := hex.DecodeString(
			"f1507d5e3f9e2fc69dce797acc3cf95c" +
				"a5636a597c9a07becb81023bae55d00d")

		ciphertext, _ := hex.DecodeString(
			"60e649ea00241fd69a3df92b82d9729d" +
				"f130ab55c66bdf03b0fcc8b70b")
		buf.EXPECT().Ciphertext().Return(ciphertext).Once()

		expPlaintext := []byte("Hello, World!")

		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, nil)
	})
}

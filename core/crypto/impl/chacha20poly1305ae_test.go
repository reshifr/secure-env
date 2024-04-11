package crypto_impl

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	cmock "github.com/reshifr/secure-env/core/crypto/mock"
	"github.com/stretchr/testify/assert"
)

func Test_ChaCha20Poly1305AE_IVLen(t *testing.T) {
	t.Parallel()
	cipher := ChaCha20Poly1305AE{}
	expIVLen := uint32(IV96Len)
	ivLen := cipher.IVLen()
	assert.Equal(t, expIVLen, ivLen)
}

func Test_ChaCha20Poly1305AE_IVFixedLen(t *testing.T) {
	t.Parallel()
	cipher := ChaCha20Poly1305AE{}
	expIVFixedLen := uint32(IV96FixedLen)
	fixedLen := cipher.IVFixedLen()
	assert.Equal(t, expIVFixedLen, fixedLen)
}

func Test_ChaCha20Poly1305AE_KeyLen(t *testing.T) {
	t.Parallel()
	cipher := ChaCha20Poly1305AE{}
	expKeyLen := uint32(ChaCha20Poly1305AEKeyLen)
	keyLen := cipher.KeyLen()
	assert.Equal(t, expKeyLen, keyLen)
}

func Test_ChaCha20Poly1305AE_MakeIV(t *testing.T) {
	t.Parallel()
	fixed := make([]byte, IV96FixedLen)
	cipher := ChaCha20Poly1305AE{}
	cipher.MakeIV(fixed)
}

func Test_ChaCha20Poly1305AE_LoadIV(t *testing.T) {
	t.Parallel()
	rawIV := make([]byte, IV96Len)
	cipher := ChaCha20Poly1305AE{}
	cipher.LoadIV(rawIV)
}

func Test_ChaCha20Poly1305AE_MakeBuf(t *testing.T) {
	t.Parallel()
	rawIV := make([]byte, IV96Len)
	ciphertext, _ := hex.DecodeString("0954115c645217e2")
	cipher := ChaCha20Poly1305AE{}
	cipher.MakeBuf(rawIV, ciphertext)
}

func Test_ChaCha20Poly1305AE_LoadBuf(t *testing.T) {
	t.Parallel()
	rawBuf, _ := hex.DecodeString("861c6c92b4cd97b487f658d0d85b445d1132f3c3")
	cipher := ChaCha20Poly1305AE{}
	cipher.LoadBuf(rawBuf)
}

func Test_ChaCha20Poly1305AE_Encrypt(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidIVLen error", func(t *testing.T) {
		t.Parallel()
		iv := cmock.NewCipherIV(t)
		iv.EXPECT().Len().Return(8).Once()
		var expBuf crypto.CipherBuf = nil
		expErr := crypto.ErrInvalidIVLen
		cipher := ChaCha20Poly1305AE{}
		buf, err := cipher.Encrypt(iv, nil, nil)
		assert.Equal(t, expBuf, buf)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("ErrInvalidKeyLen error", func(t *testing.T) {
		t.Parallel()
		iv := cmock.NewCipherIV(t)
		iv.EXPECT().Len().Return(IV96Len).Once()
		key := bytes.Repeat([]byte{0xff}, 8)
		var expBuf crypto.CipherBuf = nil
		expErr := crypto.ErrInvalidKeyLen
		cipher := ChaCha20Poly1305AE{}
		buf, err := cipher.Encrypt(iv, key, nil)
		assert.Equal(t, expBuf, buf)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		iv := cmock.NewCipherIV(t)
		iv.EXPECT().Len().Return(IV96Len).Once()
		key, _ := hex.DecodeString(
			"00b7f8ef132f263f63e9c5b61549b756" +
				"4b15b9e50eb793019c888d11f4231d00")

		fixed := uint32(0x01020304)
		invocation := uint64(1000)
		invokedRawIV := binary.BigEndian.AppendUint32(nil, fixed)
		invokedRawIV = binary.BigEndian.AppendUint64(invokedRawIV, invocation)
		invokedIV, _ := LoadIV96(invokedRawIV)
		iv.EXPECT().Invoke().Return(invokedIV).Once()

		plaintext := []byte("Hello, World!")
		ciphertext, _ := hex.DecodeString(
			"af0c76018d553a976365420ff26a7dc7" +
				"a1e95fe40a27f1e733c067b990")
		expBuf, _ := MakeIV96Buf(invokedRawIV, ciphertext)

		cipher := ChaCha20Poly1305AE{}
		buf, err := cipher.Encrypt(iv, key, plaintext)
		assert.Equal(t, buf, expBuf)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_ChaCha20Poly1305AE_Decrypt(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidRawIVLen error", func(t *testing.T) {
		t.Parallel()
		buf := cmock.NewCipherBuf(t)
		rawIV := bytes.Repeat([]byte{0xff}, 8)
		buf.EXPECT().RawIV().Return(rawIV).Once()
		var expPlaintext []byte = nil
		expErr := crypto.ErrInvalidRawIVLen
		cipher := ChaCha20Poly1305AE{}
		plaintext, err := cipher.Decrypt(nil, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("ErrInvalidKeyLen error", func(t *testing.T) {
		t.Parallel()
		buf := cmock.NewCipherBuf(t)
		rawIV := bytes.Repeat([]byte{0xff}, IV96Len)
		buf.EXPECT().RawIV().Return(rawIV).Once()
		key := bytes.Repeat([]byte{0xff}, 8)
		var expPlaintext []byte = nil
		expErr := crypto.ErrInvalidKeyLen

		cipher := ChaCha20Poly1305AE{}
		plaintext, err := cipher.Decrypt(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})

	fixed := uint32(0x01020304)
	invocation := uint64(1000)
	rawIV := binary.BigEndian.AppendUint32(nil, fixed)
	rawIV = binary.BigEndian.AppendUint64(rawIV, invocation)
	t.Run("ErrCipherAuthFailed error", func(t *testing.T) {
		t.Parallel()
		buf := cmock.NewCipherBuf(t)
		buf.EXPECT().RawIV().Return(rawIV).Once()
		key, _ := hex.DecodeString(
			"b2c1bccf1d6953bdbf5ccccc8f6355af" +
				"02b1d8c8f1e0b4fe3af9c8409be933d5")

		ciphertext, _ := hex.DecodeString(
			"af0c76018d553a976365420ff26a7dc7" +
				"a1e95fe40a27f1e733c067b990")
		buf.EXPECT().Ciphertext().Return(ciphertext).Once()
		var expPlaintext []byte = nil
		expErr := crypto.ErrCipherAuthFailed

		cipher := ChaCha20Poly1305AE{}
		plaintext, err := cipher.Decrypt(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		buf := cmock.NewCipherBuf(t)
		buf.EXPECT().RawIV().Return(rawIV).Once()
		key, _ := hex.DecodeString(
			"00b7f8ef132f263f63e9c5b61549b756" +
				"4b15b9e50eb793019c888d11f4231d00")

		ciphertext, _ := hex.DecodeString(
			"af0c76018d553a976365420ff26a7dc7" +
				"a1e95fe40a27f1e733c067b990")
		buf.EXPECT().Ciphertext().Return(ciphertext).Once()
		expPlaintext := []byte("Hello, World!")

		cipher := ChaCha20Poly1305AE{}
		plaintext, err := cipher.Decrypt(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, nil)
	})
}

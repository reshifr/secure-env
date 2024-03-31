package crypto_impl

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	mock "github.com/reshifr/secure-env/core/crypto/mock"
	"github.com/stretchr/testify/assert"
)

func Test_NewChaCha20Poly1305(t *testing.T) {
	t.Parallel()
	rng := mock.NewCSPRNG(t)
	expCipher := &ChaCha20Poly1305[*mock.CSPRNG]{csprng: rng}
	cipher := NewChaCha20Poly1305(rng)
	assert.Equal(t, expCipher, cipher)
}

func Test_ChaCha20Poly1305_KeyLen(t *testing.T) {
	t.Parallel()
	cipher := &ChaCha20Poly1305[*mock.CSPRNG]{}
	expKeyLen := uint32(ChaCha20Poly1305KeyLen)
	keyLen := cipher.KeyLen()
	assert.Equal(t, expKeyLen, keyLen)
}

func Test_ChaCha20Poly1305_IV(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidIVFixedLen error", func(t *testing.T) {
		t.Parallel()
		fixed := [2]byte{}
		var expIV *IV96 = nil
		expErr := crypto.ErrInvalidIVFixedLen
		cipher := &ChaCha20Poly1305[*mock.CSPRNG]{}
		iv, err := cipher.IV(fixed[:])
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		fixed := [IV96FixedLen]byte{}
		encFixed := uint32(0x01020304)
		binary.BigEndian.PutUint32(fixed[:], encFixed)
		invocation := uint64(0)
		expIV := &IV96{fixed: encFixed, invocation: invocation}
		cipher := &ChaCha20Poly1305[*mock.CSPRNG]{}
		iv, err := cipher.IV(fixed[:])
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_ChaCha20Poly1305_RandomIV(t *testing.T) {
	t.Parallel()
	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		rawIV := [IV96Len]byte{}
		expErr := crypto.ErrReadEntropyFailed

		rng := mock.NewCSPRNG(t)
		rng.EXPECT().Read(rawIV[:]).Return(expErr).Once()
		var expIV crypto.CipherIV = nil

		cipher := NewChaCha20Poly1305(rng)
		iv, err := cipher.RandomIV()
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		rawIV := [IV96Len]byte{}
		rng := mock.NewCSPRNG(t)
		rng.EXPECT().Read(rawIV[:]).RunAndReturn(func(block []byte) error {
			for i := 0; i < len(block); i++ {
				block[i] = 0xff
			}
			return nil
		}).Once()
		expIV := &IV96{fixed: 0xffffffff, invocation: 0xffffffffffffffff}

		cipher := NewChaCha20Poly1305(rng)
		iv, err := cipher.RandomIV()
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_ChaCha20Poly1305_Seal(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidIVLen error", func(t *testing.T) {
		t.Parallel()
		iv := mock.NewCipherIV(t)
		iv.EXPECT().Len().Return(8).Once()
		var expBuf crypto.CipherBuf = nil
		expErr := crypto.ErrInvalidIVLen

		cipher := &ChaCha20Poly1305[*mock.CSPRNG]{}
		buf, err := cipher.Seal(iv, nil, nil)
		assert.Equal(t, expBuf, buf)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("ErrInvalidKeyLen error", func(t *testing.T) {
		t.Parallel()
		iv := mock.NewCipherIV(t)
		iv.EXPECT().Len().Return(IV96Len).Once()
		key := bytes.Repeat([]byte{0xff}, 8)
		var expBuf crypto.CipherBuf = nil
		expErr := crypto.ErrInvalidKeyLen

		cipher := &ChaCha20Poly1305[*mock.CSPRNG]{}
		buf, err := cipher.Seal(iv, key, nil)
		assert.Equal(t, expBuf, buf)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		iv := mock.NewCipherIV(t)
		iv.EXPECT().Len().Return(IV96Len).Once()

		key := bytes.Repeat([]byte{0xff}, ChaCha20Poly1305KeyLen)
		add := [ChaCha20Poly1305AddLen]byte{}
		expErr := crypto.ErrReadEntropyFailed

		rng := mock.NewCSPRNG(t)
		rng.EXPECT().Read(add[:]).Return(expErr).Once()
		var expBuf crypto.CipherBuf = nil

		cipher := NewChaCha20Poly1305(rng)
		buf, err := cipher.Seal(iv, key, nil)
		assert.Equal(t, expBuf, buf)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		iv := mock.NewCipherIV(t)
		iv.EXPECT().Len().Return(IV96Len).Once()
		key, _ := hex.DecodeString(
			"00b7f8ef132f263f63e9c5b61549b756" +
				"4b15b9e50eb793019c888d11f4231d00")

		rng := mock.NewCSPRNG(t)
		vAdd := [ChaCha20Poly1305AddLen]byte{}
		add, _ := hex.DecodeString("00401aa5699c9102659eb2238c8d3348")
		rng.EXPECT().Read(vAdd[:]).RunAndReturn(func(block []byte) error {
			copy(block, add[:])
			return nil
		}).Once()
		expVAdd := [ChaCha20Poly1305AddLen]byte{}
		copy(expVAdd[:], add)

		fixed := uint32(0x01020304)
		invocation := uint64(1000)
		rawInvokedIV := binary.BigEndian.AppendUint32(nil, fixed)
		rawInvokedIV = binary.BigEndian.AppendUint64(rawInvokedIV, invocation)
		invokedIV, _ := LoadIV96(rawInvokedIV)
		iv.EXPECT().Invoke().Return(invokedIV).Once()

		plaintext := []byte("jcATNy6yermUfxbU0S@rzc+05p~2W+AD")
		ciphertext, _ := hex.DecodeString(
			"8d0a5b39ac002cb96965433eb50889c0" +
				"c4b1471d141d44698078af6429f1d3c7" +
				"720c9f9902b1de911fff64bb9020e385")
		expBuf, _ := MakeChaCha20Poly1305Buf(invokedIV, expVAdd, ciphertext)

		cipher := NewChaCha20Poly1305(rng)
		buf, err := cipher.Seal(iv, key, plaintext)
		assert.Equal(t, buf, expBuf)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_ChaCha20Poly1305_Open(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidRawIVLen error", func(t *testing.T) {
		t.Parallel()
		buf := mock.NewCipherBuf(t)
		rawIV := bytes.Repeat([]byte{0xff}, 8)
		buf.EXPECT().RawIV().Return(rawIV).Once()
		var expPlaintext []byte = nil
		expErr := crypto.ErrInvalidRawIVLen

		cipher := &ChaCha20Poly1305[*mock.CSPRNG]{}
		plaintext, err := cipher.Open(nil, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("ErrInvalidKeyLen error", func(t *testing.T) {
		t.Parallel()
		buf := mock.NewCipherBuf(t)
		rawIV := bytes.Repeat([]byte{0xff}, IV96Len)
		buf.EXPECT().RawIV().Return(rawIV).Once()
		key := bytes.Repeat([]byte{0xff}, 8)
		var expPlaintext []byte = nil
		expErr := crypto.ErrInvalidKeyLen

		cipher := &ChaCha20Poly1305[*mock.CSPRNG]{}
		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Wrong key", func(t *testing.T) {
		t.Parallel()
		buf := mock.NewCipherBuf(t)
		rawIV, _ := hex.DecodeString("0102030400000000000003e8")
		buf.EXPECT().RawIV().Return(rawIV).Once()
		key, _ := hex.DecodeString(
			"237a313dfa9b24a88d9bd0b8ba943f5e" +
				"5584ec04e7cc9b887fa7840c88391f1b")

		add, _ := hex.DecodeString("f1bf66c9135fd818d5a078b4e9a871c4")
		buf.EXPECT().Add().Return(add).Once()
		ciphertext, _ := hex.DecodeString(
			"a7b92ad0c394441c26de83c650b9b18e" +
				"4de70fffa5a9ab37a827e3cbf9848a18" +
				"f130823fb58faea53ba13474024d3d20")
		buf.EXPECT().Ciphertext().Return(ciphertext).Once()
		var expPlaintext []byte = nil
		expErr := crypto.ErrCipherAuthFailed

		cipher := &ChaCha20Poly1305[*mock.CSPRNG]{}
		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Wrong iv", func(t *testing.T) {
		t.Parallel()
		buf := mock.NewCipherBuf(t)
		rawIV, _ := hex.DecodeString("0102030400000000000003e9")
		buf.EXPECT().RawIV().Return(rawIV).Once()
		key, _ := hex.DecodeString(
			"d5ba893af8e8c9a756bf7e7daf1e3351" +
				"31c59f72b7240ecda34da884cf822de4")

		add, _ := hex.DecodeString("f1bf66c9135fd818d5a078b4e9a871c4")
		buf.EXPECT().Add().Return(add).Once()
		ciphertext, _ := hex.DecodeString(
			"a7b92ad0c394441c26de83c650b9b18e" +
				"4de70fffa5a9ab37a827e3cbf9848a18" +
				"f130823fb58faea53ba13474024d3d20")
		buf.EXPECT().Ciphertext().Return(ciphertext).Once()
		var expPlaintext []byte = nil
		expErr := crypto.ErrCipherAuthFailed

		cipher := &ChaCha20Poly1305[*mock.CSPRNG]{}
		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Wrong add", func(t *testing.T) {
		t.Parallel()
		buf := mock.NewCipherBuf(t)
		rawIV, _ := hex.DecodeString("0102030400000000000003e8")
		buf.EXPECT().RawIV().Return(rawIV).Once()
		key, _ := hex.DecodeString(
			"d5ba893af8e8c9a756bf7e7daf1e3351" +
				"31c59f72b7240ecda34da884cf822de4")

		add, _ := hex.DecodeString("66845d08e6ab9555a0fa5f3586a1921e")
		buf.EXPECT().Add().Return(add).Once()
		ciphertext, _ := hex.DecodeString(
			"a7b92ad0c394441c26de83c650b9b18e" +
				"4de70fffa5a9ab37a827e3cbf9848a18" +
				"f130823fb58faea53ba13474024d3d20")
		buf.EXPECT().Ciphertext().Return(ciphertext).Once()
		var expPlaintext []byte = nil
		expErr := crypto.ErrCipherAuthFailed

		cipher := &ChaCha20Poly1305[*mock.CSPRNG]{}
		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Wrong ciphertext", func(t *testing.T) {
		t.Parallel()
		buf := mock.NewCipherBuf(t)
		rawIV, _ := hex.DecodeString("0102030400000000000003e8")
		buf.EXPECT().RawIV().Return(rawIV).Once()
		key, _ := hex.DecodeString(
			"d5ba893af8e8c9a756bf7e7daf1e3351" +
				"31c59f72b7240ecda34da884cf822de4")

		add, _ := hex.DecodeString("f1bf66c9135fd818d5a078b4e9a871c4")
		buf.EXPECT().Add().Return(add).Once()
		ciphertext, _ := hex.DecodeString(
			"8d0a5b39ac002cb96965433eb50889c0" +
				"c4b1471d141d44698078af6429f1d3c7" +
				"720c9f9902b1de911fff64bb9020e385")
		buf.EXPECT().Ciphertext().Return(ciphertext).Once()
		var expPlaintext []byte = nil
		expErr := crypto.ErrCipherAuthFailed

		cipher := &ChaCha20Poly1305[*mock.CSPRNG]{}
		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		buf := mock.NewCipherBuf(t)
		rawIV, _ := hex.DecodeString("0102030400000000000003e8")
		buf.EXPECT().RawIV().Return(rawIV).Once()
		key, _ := hex.DecodeString(
			"d5ba893af8e8c9a756bf7e7daf1e3351" +
				"31c59f72b7240ecda34da884cf822de4")

		add, _ := hex.DecodeString("f1bf66c9135fd818d5a078b4e9a871c4")
		buf.EXPECT().Add().Return(add).Once()
		ciphertext, _ := hex.DecodeString(
			"a7b92ad0c394441c26de83c650b9b18e" +
				"4de70fffa5a9ab37a827e3cbf9848a18" +
				"f130823fb58faea53ba13474024d3d20")
		buf.EXPECT().Ciphertext().Return(ciphertext).Once()
		expPlaintext := []byte("hlu/8djzREmN.y45arUs&uPn7piEnei1")

		cipher := &ChaCha20Poly1305[*mock.CSPRNG]{}
		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, nil)
	})
}

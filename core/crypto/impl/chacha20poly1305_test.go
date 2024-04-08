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

func Test_NewChaCha20Poly1305(t *testing.T) {
	t.Parallel()
	rng := cmock.NewCSPRNG(t)
	expCipher := &ChaCha20Poly1305[*cmock.CSPRNG]{csprng: rng}
	cipher := NewChaCha20Poly1305(rng)
	assert.Equal(t, expCipher, cipher)
}

func Test_ChaCha20Poly1305_KeyLen(t *testing.T) {
	t.Parallel()
	cipher := &ChaCha20Poly1305[*cmock.CSPRNG]{}
	expKeyLen := uint32(ChaCha20Poly1305KeyLen)
	keyLen := cipher.KeyLen()
	assert.Equal(t, expKeyLen, keyLen)
}

func Test_ChaCha20Poly1305_Seal(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidIVLen error", func(t *testing.T) {
		t.Parallel()
		iv := cmock.NewCipherIV(t)
		iv.EXPECT().Len().Return(8).Once()
		var expBuf crypto.CipherBuf = nil
		expErr := crypto.ErrInvalidIVLen

		cipher := &ChaCha20Poly1305[*cmock.CSPRNG]{}
		buf, err := cipher.Seal(iv, nil, nil)
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

		cipher := &ChaCha20Poly1305[*cmock.CSPRNG]{}
		buf, err := cipher.Seal(iv, key, nil)
		assert.Equal(t, expBuf, buf)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		iv := cmock.NewCipherIV(t)
		iv.EXPECT().Len().Return(IV96Len).Once()

		key := bytes.Repeat([]byte{0xff}, ChaCha20Poly1305KeyLen)
		ad := [ChaCha20Poly1305ADLen]byte{}
		expErr := crypto.ErrReadEntropyFailed

		rng := cmock.NewCSPRNG(t)
		rng.EXPECT().Read(ad[:]).Return(expErr).Once()
		var expBuf crypto.CipherBuf = nil

		cipher := NewChaCha20Poly1305(rng)
		buf, err := cipher.Seal(iv, key, nil)
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

		rng := cmock.NewCSPRNG(t)
		vAD := [ChaCha20Poly1305ADLen]byte{}
		ad, _ := hex.DecodeString("00401aa5699c9102659eb2238c8d3348")
		rng.EXPECT().Read(vAD[:]).RunAndReturn(func(block []byte) error {
			copy(block, ad)
			return nil
		}).Once()

		fixed := uint32(0x01020304)
		invocation := uint64(1000)
		invokedRawIV := binary.BigEndian.AppendUint32(nil, fixed)
		invokedRawIV = binary.BigEndian.AppendUint64(invokedRawIV, invocation)
		invokedIV, _ := LoadIV96(invokedRawIV)
		iv.EXPECT().Invoke().Return(invokedIV).Once()

		plaintext := []byte("jcATNy6yermUfxbU0S@rzc+05p~2W+AD")
		ciphertext, _ := hex.DecodeString(
			"8d0a5b39ac002cb96965433eb50889c0" +
				"c4b1471d141d44698078af6429f1d3c7" +
				"720c9f9902b1de911fff64bb9020e385")
		expBuf, _ := MakeChaCha20Poly1305Buf(invokedRawIV, ad, ciphertext)

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
		buf := cmock.NewCipherBuf(t)
		rawIV := bytes.Repeat([]byte{0xff}, 8)
		buf.EXPECT().RawIV().Return(rawIV).Once()
		var expPlaintext []byte = nil
		expErr := crypto.ErrInvalidRawIVLen

		cipher := &ChaCha20Poly1305[*cmock.CSPRNG]{}
		plaintext, err := cipher.Open(nil, buf)
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

		cipher := &ChaCha20Poly1305[*cmock.CSPRNG]{}
		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Wrong key", func(t *testing.T) {
		t.Parallel()
		buf := cmock.NewCipherBuf(t)
		rawIV, _ := hex.DecodeString("0102030400000000000003e8")
		buf.EXPECT().RawIV().Return(rawIV).Once()
		key, _ := hex.DecodeString(
			"237a313dfa9b24a88d9bd0b8ba943f5e" +
				"5584ec04e7cc9b887fa7840c88391f1b")

		ad, _ := hex.DecodeString("f1bf66c9135fd818d5a078b4e9a871c4")
		buf.EXPECT().AD().Return(ad).Once()
		ciphertext, _ := hex.DecodeString(
			"a7b92ad0c394441c26de83c650b9b18e" +
				"4de70fffa5a9ab37a827e3cbf9848a18" +
				"f130823fb58faea53ba13474024d3d20")
		buf.EXPECT().Ciphertext().Return(ciphertext).Once()
		var expPlaintext []byte = nil
		expErr := crypto.ErrCipherAuthFailed

		cipher := &ChaCha20Poly1305[*cmock.CSPRNG]{}
		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Wrong iv", func(t *testing.T) {
		t.Parallel()
		buf := cmock.NewCipherBuf(t)
		rawIV, _ := hex.DecodeString("0102030400000000000003e9")
		buf.EXPECT().RawIV().Return(rawIV).Once()
		key, _ := hex.DecodeString(
			"d5ba893af8e8c9a756bf7e7daf1e3351" +
				"31c59f72b7240ecda34da884cf822de4")

		ad, _ := hex.DecodeString("f1bf66c9135fd818d5a078b4e9a871c4")
		buf.EXPECT().AD().Return(ad).Once()
		ciphertext, _ := hex.DecodeString(
			"a7b92ad0c394441c26de83c650b9b18e" +
				"4de70fffa5a9ab37a827e3cbf9848a18" +
				"f130823fb58faea53ba13474024d3d20")
		buf.EXPECT().Ciphertext().Return(ciphertext).Once()
		var expPlaintext []byte = nil
		expErr := crypto.ErrCipherAuthFailed

		cipher := &ChaCha20Poly1305[*cmock.CSPRNG]{}
		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Wrong ad", func(t *testing.T) {
		t.Parallel()
		buf := cmock.NewCipherBuf(t)
		rawIV, _ := hex.DecodeString("0102030400000000000003e8")
		buf.EXPECT().RawIV().Return(rawIV).Once()
		key, _ := hex.DecodeString(
			"d5ba893af8e8c9a756bf7e7daf1e3351" +
				"31c59f72b7240ecda34da884cf822de4")

		ad, _ := hex.DecodeString("66845d08e6ab9555a0fa5f3586a1921e")
		buf.EXPECT().AD().Return(ad).Once()
		ciphertext, _ := hex.DecodeString(
			"a7b92ad0c394441c26de83c650b9b18e" +
				"4de70fffa5a9ab37a827e3cbf9848a18" +
				"f130823fb58faea53ba13474024d3d20")
		buf.EXPECT().Ciphertext().Return(ciphertext).Once()
		var expPlaintext []byte = nil
		expErr := crypto.ErrCipherAuthFailed

		cipher := &ChaCha20Poly1305[*cmock.CSPRNG]{}
		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Wrong ciphertext", func(t *testing.T) {
		t.Parallel()
		buf := cmock.NewCipherBuf(t)
		rawIV, _ := hex.DecodeString("0102030400000000000003e8")
		buf.EXPECT().RawIV().Return(rawIV).Once()
		key, _ := hex.DecodeString(
			"d5ba893af8e8c9a756bf7e7daf1e3351" +
				"31c59f72b7240ecda34da884cf822de4")

		ad, _ := hex.DecodeString("f1bf66c9135fd818d5a078b4e9a871c4")
		buf.EXPECT().AD().Return(ad).Once()
		ciphertext, _ := hex.DecodeString(
			"8d0a5b39ac002cb96965433eb50889c0" +
				"c4b1471d141d44698078af6429f1d3c7" +
				"720c9f9902b1de911fff64bb9020e385")
		buf.EXPECT().Ciphertext().Return(ciphertext).Once()
		var expPlaintext []byte = nil
		expErr := crypto.ErrCipherAuthFailed

		cipher := &ChaCha20Poly1305[*cmock.CSPRNG]{}
		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		buf := cmock.NewCipherBuf(t)
		rawIV, _ := hex.DecodeString("0102030400000000000003e8")
		buf.EXPECT().RawIV().Return(rawIV).Once()
		key, _ := hex.DecodeString(
			"d5ba893af8e8c9a756bf7e7daf1e3351" +
				"31c59f72b7240ecda34da884cf822de4")

		ad, _ := hex.DecodeString("f1bf66c9135fd818d5a078b4e9a871c4")
		buf.EXPECT().AD().Return(ad).Once()
		ciphertext, _ := hex.DecodeString(
			"a7b92ad0c394441c26de83c650b9b18e" +
				"4de70fffa5a9ab37a827e3cbf9848a18" +
				"f130823fb58faea53ba13474024d3d20")
		buf.EXPECT().Ciphertext().Return(ciphertext).Once()
		expPlaintext := []byte("hlu/8djzREmN.y45arUs&uPn7piEnei1")

		cipher := &ChaCha20Poly1305[*cmock.CSPRNG]{}
		plaintext, err := cipher.Open(key, buf)
		assert.Equal(t, expPlaintext, plaintext)
		assert.ErrorIs(t, err, nil)
	})
}

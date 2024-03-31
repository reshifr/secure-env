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
		var expCiphertext []byte = nil
		expErr := crypto.ErrInvalidRawIVLen

		cipher := &ChaCha20Poly1305[*mock.CSPRNG]{}
		ciphertext, err := cipher.Open(nil, buf)
		assert.Equal(t, expCiphertext, ciphertext)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("ErrInvalidKeyLen error", func(t *testing.T) {
		t.Parallel()
		buf := mock.NewCipherBuf(t)
		rawIV := bytes.Repeat([]byte{0xff}, IV96Len)
		buf.EXPECT().RawIV().Return(rawIV).Once()
		key := bytes.Repeat([]byte{0xff}, 8)
		var expCiphertext []byte = nil
		expErr := crypto.ErrInvalidKeyLen

		cipher := &ChaCha20Poly1305[*mock.CSPRNG]{}
		ciphertext, err := cipher.Open(key, buf)
		assert.Equal(t, expCiphertext, ciphertext)
		assert.ErrorIs(t, err, expErr)
	})

	// t.Run("", func(t *testing.T) {
	// 	t.Parallel()
	// 	iv := mock.NewCipherIV(t)
	// 	iv.EXPECT().Len().Return(IV96Len).Once()
	// 	key := bytes.Repeat([]byte{0xff}, 8)

	// 	var expCiphertext []byte = nil
	// 	expErr := crypto.ErrInvalidKeyLen

	// 	cipher := &ChaCha20Poly1305[*mock.CSPRNG]{}
	// 	ciphertext, err := cipher.Open(iv, key, nil)
	// 	assert.Equal(t, expCiphertext, ciphertext)
	// 	assert.ErrorIs(t, err, expErr)
	// })
}

package crypto_impl

import (
	"encoding/binary"
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
		rng := mock.NewCSPRNG(t)
		rawIV := [IV96Len]byte{}
		expErr := crypto.ErrReadEntropyFailed
		rng.EXPECT().Read(rawIV[:]).Return(expErr).Once()
		var expIV crypto.CipherIV = nil
		cipher := NewChaCha20Poly1305(rng)
		iv, err := cipher.RandomIV()
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		rng := mock.NewCSPRNG(t)
		rawIV := [IV96Len]byte{}
		rng.EXPECT().Read(rawIV[:]).RunAndReturn(func(b []byte) error {
			for i := 0; i < len(b); i++ {
				b[i] = 0xff
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

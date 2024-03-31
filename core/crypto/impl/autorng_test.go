package crypto_impl

import (
	"bytes"
	"errors"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	"github.com/stretchr/testify/assert"
)

func Test_NewAutoRNG(t *testing.T) {
	t.Parallel()
	fn := crypto.FnCSPRNG{}
	expRNG := AutoRNG{fnCSPRNG: fn}
	rng := NewAutoRNG(fn)
	assert.Equal(t, expRNG, rng)
}

func Test_AutoRNG_Make(t *testing.T) {
	t.Parallel()
	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		fn := crypto.FnCSPRNG{
			Read: func([]byte) (int, error) {
				return 0, errors.New("")
			},
		}
		var expBlock []byte = nil
		expErr := crypto.ErrReadEntropyFailed
		rng := NewAutoRNG(fn)
		block, err := rng.Make(8)
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		fn := crypto.FnCSPRNG{
			Read: func(block []byte) (n int, err error) {
				n = len(block)
				for i := 0; i < n; i++ {
					block[i] = 0xff
				}
				return n, nil
			},
		}
		expBlock := bytes.Repeat([]byte{0xff}, 8)
		rng := NewAutoRNG(fn)
		block, err := rng.Make(8)
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_AutoRNG_Read(t *testing.T) {
	t.Parallel()
	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		fn := crypto.FnCSPRNG{
			Read: func([]byte) (int, error) {
				return 0, errors.New("")
			},
		}
		expBlock := [8]byte{}
		expErr := crypto.ErrReadEntropyFailed

		block := [8]byte{}
		rng := NewAutoRNG(fn)
		err := rng.Read(block[:])
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		fn := crypto.FnCSPRNG{
			Read: func(block []byte) (int, error) {
				n := len(block)
				for i := 0; i < n; i++ {
					block[i] = 0xff
				}
				return n, nil
			},
		}
		expBlock := bytes.Repeat([]byte{0xff}, 8)

		block := make([]byte, 8)
		rng := NewAutoRNG(fn)
		err := rng.Read(block[:])
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, nil)
	})
}

package crypto_impl

import (
	"bytes"
	"errors"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	"github.com/stretchr/testify/assert"
)

func Test_NewStdRNG(t *testing.T) {
	t.Parallel()
	fn := FnStdRNG{}
	expRNG := StdRNG{fn: fn}

	rng := NewStdRNG(fn)
	assert.Equal(t, expRNG, rng)
}

func Test_StdRNG_Block(t *testing.T) {
	t.Parallel()
	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		fn := FnStdRNG{
			Read: func([]byte) (int, error) {
				return 0, errors.New("")
			},
		}
		var expBlock []byte = nil
		const expErr = crypto.ErrReadEntropyFailed

		rng := NewStdRNG(fn)
		block, err := rng.Block(8)
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		expBlock := bytes.Repeat([]byte{0xff}, 8)
		fn := FnStdRNG{
			Read: func(block []byte) (n int, err error) {
				copy(block, expBlock)
				return len(block), nil
			},
		}

		rng := NewStdRNG(fn)
		block, err := rng.Block(8)
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_StdRNG_Read(t *testing.T) {
	t.Parallel()
	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		fn := FnStdRNG{
			Read: func([]byte) (int, error) {
				return 0, errors.New("")
			},
		}
		block := make([]byte, 8)
		expBlock := bytes.Clone(block)
		const expErr = crypto.ErrReadEntropyFailed

		rng := NewStdRNG(fn)
		err := rng.Read(block)
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		block := make([]byte, 8)
		expBlock := bytes.Repeat([]byte{0xff}, 8)
		fn := FnStdRNG{
			Read: func(block []byte) (int, error) {
				copy(block, expBlock)
				return len(block), nil
			},
		}

		rng := NewStdRNG(fn)
		err := rng.Read(block)
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, nil)
	})
}

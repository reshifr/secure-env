package crypt

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_OpenAutoRNG(t *testing.T) {
	t.Parallel()
	fn := FnCSPRNG{}
	expRNG := &AutoRNG{fnCSPRNG: fn}

	rng := OpenAutoRNG(fn)
	assert.Equal(t, expRNG, rng)
}

func Test_AutoRNG_Make(t *testing.T) {
	t.Parallel()
	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		fn := FnCSPRNG{
			Read: func(b []byte) (int, error) {
				return 0, errors.New("")
			},
		}
		var expBlock []byte = nil
		expErr := ErrReadEntropyFailed

		csprng := &AutoRNG{fnCSPRNG: fn}
		block, err := csprng.Make(4)
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		fn := FnCSPRNG{
			Read: func(b []byte) (n int, err error) {
				n = len(b)
				for i := 0; i < n; i++ {
					b[i] = 0xff
				}
				return n, nil
			},
		}
		expBlock := []byte{0xff, 0xff, 0xff, 0xff}

		csprng := &AutoRNG{fnCSPRNG: fn}
		block, err := csprng.Make(4)
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_AutoRNG_Read(t *testing.T) {
	t.Parallel()
	t.Run("ErrReadEntropyFailed error", func(t *testing.T) {
		t.Parallel()
		fn := FnCSPRNG{
			Read: func(b []byte) (int, error) {
				return 0, errors.New("")
			},
		}
		expBlock := [4]byte{}
		expErr := ErrReadEntropyFailed

		block := [4]byte{}
		csprng := &AutoRNG{fnCSPRNG: fn}
		err := csprng.Read(block[:])
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		fn := FnCSPRNG{
			Read: func(b []byte) (int, error) {
				n := len(b)
				for i := 0; i < n; i++ {
					b[i] = 0xff
				}
				return n, nil
			},
		}
		expBlock := [4]byte{0xff, 0xff, 0xff, 0xff}

		block := [4]byte{}
		csprng := &AutoRNG{fnCSPRNG: fn}
		err := csprng.Read(block[:])
		assert.Equal(t, expBlock, block)
		assert.ErrorIs(t, err, nil)
	})
}

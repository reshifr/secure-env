package crypt

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_CSPRNGError_Error(t *testing.T) {
	t.Parallel()
	err := ErrCSPRNGRead
	expMsg := "ErrCSPRNGRead: " +
		"Failed to read a random value from the entropy sources."

	msg := err.Error()
	assert.Equal(t, expMsg, msg)
}

func Test_NewAutoRNG(t *testing.T) {
	t.Parallel()
	csprngFn := FnCSPRNG{}
	expRNG := &AutoRNG{csprngFn: csprngFn}

	rng := NewAutoRNG(csprngFn)
	assert.Equal(t, expRNG, rng)
}

func Test_AutoRNG_Read(t *testing.T) {
	t.Parallel()
	t.Run("Failed to read", func(t *testing.T) {
		t.Parallel()
		csprngFn := FnCSPRNG{
			Read: func(b []byte) (int, error) {
				return 0, errors.New("")
			},
		}
		expB := [4]byte{}
		expErr := ErrCSPRNGRead

		b := [4]byte{}
		csprng := &AutoRNG{csprngFn: csprngFn}
		err := csprng.Read(b[:])
		assert.Equal(t, expB, b)
		assert.ErrorIs(t, err, expErr)
	})

	t.Run("Succeed to read", func(t *testing.T) {
		t.Parallel()
		csprngFn := FnCSPRNG{
			Read: func(b []byte) (int, error) {
				n := len(b)
				for i := 0; i < n; i++ {
					b[i] = 0xff
				}
				return n, nil
			},
		}
		expB := [4]byte{0xff, 0xff, 0xff, 0xff}

		var b [4]byte
		csprng := &AutoRNG{csprngFn: csprngFn}
		err := csprng.Read(b[:])
		assert.Equal(t, expB, b)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_AutoRNG_Make(t *testing.T) {
	t.Parallel()
	t.Run("Failed to read", func(t *testing.T) {
		t.Parallel()
		csprngFn := FnCSPRNG{
			Read: func(b []byte) (int, error) {
				return 0, errors.New("")
			},
		}
		expB := make([]byte, 4)
		expErr := ErrCSPRNGRead

		csprng := &AutoRNG{csprngFn: csprngFn}
		b, err := csprng.Make(4)
		assert.Equal(t, expB, b)
		assert.ErrorIs(t, err, expErr)
	})

	t.Run("Succeed to read", func(t *testing.T) {
		t.Parallel()
		csprngFn := FnCSPRNG{
			Read: func(b []byte) (n int, err error) {
				n = len(b)
				for i := 0; i < n; i++ {
					b[i] = 0xff
				}
				return n, nil
			},
		}
		expB := []byte{0xff, 0xff, 0xff, 0xff}

		csprng := &AutoRNG{csprngFn: csprngFn}
		b, err := csprng.Make(4)
		assert.Equal(t, expB, b)
		assert.ErrorIs(t, err, nil)
	})
}

package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_CipherError_Error(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidIVLen value", func(t *testing.T) {
		t.Parallel()
		err := ErrInvalidIVLen
		expMsg := "ErrInvalidIVLen: invalid IV length."

		msg := err.Error()
		assert.Equal(t, expMsg, msg)
	})
	t.Run("ErrInvalidKeyLen value", func(t *testing.T) {
		t.Parallel()
		err := ErrInvalidKeyLen
		expMsg := "ErrInvalidKeyLen: invalid key length."

		msg := err.Error()
		assert.Equal(t, expMsg, msg)
	})
	t.Run("ErrInvalidBufferLayout value", func(t *testing.T) {
		t.Parallel()
		err := ErrInvalidBufferLayout
		expMsg := "ErrInvalidBufferLayout: the buffer structure cannot be read."

		msg := err.Error()
		assert.Equal(t, expMsg, msg)
	})
	t.Run("ErrCipherAuthFailed value", func(t *testing.T) {
		t.Parallel()
		err := ErrCipherAuthFailed
		expMsg := "ErrCipherAuthFailed: failed to decrypt the data."

		msg := err.Error()
		assert.Equal(t, expMsg, msg)
	})
	t.Run("Unknown value", func(t *testing.T) {
		t.Parallel()
		err := CipherError(957361)
		expMsg := "Error: unknown."

		msg := err.Error()
		assert.Equal(t, expMsg, msg)
	})
}

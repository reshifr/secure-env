package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_CipherError_Error(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidIVLen value", func(t *testing.T) {
		t.Parallel()
		const err = ErrInvalidIVLen
		const expMsg = "ErrInvalidIVLen: invalid IV length."

		msg := err.Error()
		assert.Equal(t, expMsg, msg)
	})
	t.Run("ErrInvalidKeyLen value", func(t *testing.T) {
		t.Parallel()
		const err = ErrInvalidKeyLen
		const expMsg = "ErrInvalidKeyLen: invalid key length."

		msg := err.Error()
		assert.Equal(t, expMsg, msg)
	})
	t.Run("ErrInvalidBufLayout value", func(t *testing.T) {
		t.Parallel()
		const err = ErrInvalidBufLayout
		const expMsg = "ErrInvalidBufLayout: the buffer structure cannot be read."

		msg := err.Error()
		assert.Equal(t, expMsg, msg)
	})
	t.Run("ErrAuthFailed value", func(t *testing.T) {
		t.Parallel()
		const err = ErrAuthFailed
		const expMsg = "ErrAuthFailed: failed to decrypt the data."

		msg := err.Error()
		assert.Equal(t, expMsg, msg)
	})
	t.Run("Unknown value", func(t *testing.T) {
		t.Parallel()
		const err = AEError(957361)
		const expMsg = "Error: unknown."

		msg := err.Error()
		assert.Equal(t, expMsg, msg)
	})
}

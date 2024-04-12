package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_CSPRNGError_Error(t *testing.T) {
	t.Parallel()
	t.Run("ErrReadEntropyFailed value", func(t *testing.T) {
		t.Parallel()
		const err = ErrReadEntropyFailed
		const expMsg = "ErrReadEntropyFailed: " +
			"Failed to read a random value from the entropy sources."

		msg := err.Error()
		assert.Equal(t, expMsg, msg)
	})
	t.Run("Unknown value", func(t *testing.T) {
		t.Parallel()
		const err = CSPRNGError(957361)
		const expMsg = "Error: unknown."

		msg := err.Error()
		assert.Equal(t, expMsg, msg)
	})
}

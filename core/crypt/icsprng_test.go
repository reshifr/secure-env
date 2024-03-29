package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_CSPRNGError_Error(t *testing.T) {
	t.Parallel()
	err := ErrReadEntropyFailed
	expMsg := "ErrReadEntropyFailed: " +
		"Failed to read a random value from the entropy sources."

	msg := err.Error()
	assert.Equal(t, expMsg, msg)
}

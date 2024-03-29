package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_IVError_Error(t *testing.T) {
	t.Parallel()
	err := ErrInvalidRawIVLen
	expMsg := "ErrInvalidRawIVLen: invalid raw IV size."

	msg := err.Error()
	assert.Equal(t, expMsg, msg)
}

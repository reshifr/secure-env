package crypt

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_MakeIV96(t *testing.T) {
	t.Parallel()
	ivId := uint32(0x01020304)
	ivIncrement := uint64(0)
	expIV := &IV96{id: ivId, increment: ivIncrement}

	iv := MakeIV96(ivId)
	assert.Equal(t, expIV, iv)
}

func Test_LoadIV96(t *testing.T) {
	t.Parallel()
	t.Run("Invalid raw IV size", func(t *testing.T) {
		t.Parallel()
		rawIV := []byte{0xff, 0xff, 0xff}
		var expIV *IV96 = nil
		expErr := ErrInvalidRawIVLen

		iv, err := LoadIV96(rawIV)
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Valid raw IV size", func(t *testing.T) {
		t.Parallel()
		ivId := uint32(0x01020304)
		ivIncrement := uint64(0x0b16212c37424d58)
		rawIV := binary.BigEndian.AppendUint32(nil, ivId)
		rawIV = binary.BigEndian.AppendUint64(rawIV, ivIncrement)
		expIV := &IV96{id: ivId, increment: ivIncrement}

		iv, err := LoadIV96(rawIV)
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_IV96_Len(t *testing.T) {
	t.Parallel()
	iv := &IV96{}
	expIVLen := iv96Len

	ivLen := iv.Len()
	assert.Equal(t, expIVLen, ivLen)
}

func Test_IV96_Invoke(t *testing.T) {
	t.Parallel()
	ivId := uint32(0x01020304)
	ivIncrement := uint64(0)
	executed := uint64(999)
	iv := &IV96{id: ivId, increment: ivIncrement}
	expIV := &IV96{id: ivId, increment: executed}

	for i := ivIncrement; i < executed; i++ {
		iv.Invoke()
	}
	assert.Equal(t, expIV, iv)
}

func Test_IV96_Raw(t *testing.T) {
	t.Parallel()
	ivId := uint32(0x01020304)
	ivIncrement := uint64(0x0b16212c37424d58)
	iv := &IV96{id: ivId, increment: ivIncrement}
	expRawIV := binary.BigEndian.AppendUint32(nil, ivId)
	expRawIV = binary.BigEndian.AppendUint64(expRawIV, ivIncrement)

	rawIV := iv.Raw()
	assert.Equal(t, expRawIV, rawIV)
}

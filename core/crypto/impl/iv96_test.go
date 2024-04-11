package crypto_impl

import (
	"encoding/binary"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	"github.com/stretchr/testify/assert"
)

func Test_MakeIV96(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidIVFixedLen error", func(t *testing.T) {
		t.Parallel()
		fixed := [2]byte{}
		var expIV *IV96 = nil
		expErr := crypto.ErrInvalidIVFixedLen
		iv, err := MakeIV96(fixed[:])
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		fixed := [IV96FixedLen]byte{}
		encFixed := uint32(0x01020304)
		binary.BigEndian.PutUint32(fixed[:], encFixed)
		invocation := uint64(0)
		expIV := &IV96{fixed: encFixed, invocation: invocation}
		iv, err := MakeIV96(fixed[:])
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_LoadIV96(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidRawIVLen error", func(t *testing.T) {
		t.Parallel()
		rawIV := [4]byte{}
		var expIV *IV96 = nil
		expErr := crypto.ErrInvalidRawIVLen
		iv, err := LoadIV96(rawIV[:])
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		fixed := uint32(0x01020304)
		invocation := uint64(0x0b16212c37424d58)
		rawIV := [IV96Len]byte{}
		binary.BigEndian.PutUint32(rawIV[:IV96FixedLen], fixed)
		binary.BigEndian.PutUint64(rawIV[IV96FixedLen:IV96Len], invocation)
		expIV := &IV96{fixed: fixed, invocation: invocation}
		iv, err := LoadIV96(rawIV[:])
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_IV96_Len(t *testing.T) {
	t.Parallel()
	iv := &IV96{}
	expIVLen := uint32(IV96Len)
	ivLen := iv.Len()
	assert.Equal(t, expIVLen, ivLen)
}

func Test_IV96_FixedLen(t *testing.T) {
	t.Parallel()
	iv := &IV96{}
	expIVLen := uint32(IV96FixedLen)
	ivLen := iv.FixedLen()
	assert.Equal(t, expIVLen, ivLen)
}

func Test_IV96_Invoke(t *testing.T) {
	t.Parallel()
	fixed := binary.BigEndian.AppendUint32(nil, 0x01020304)
	iv, _ := MakeIV96(fixed)
	executed := uint64(1000)
	rawIV := binary.BigEndian.AppendUint32(nil, 0x01020304)
	rawIV = binary.BigEndian.AppendUint64(rawIV, executed)
	expIV, _ := LoadIV96(rawIV)
	for i := 0; i < int(executed); i++ {
		iv.Invoke()
	}
	assert.Equal(t, expIV, iv)
}

func Test_IV96_Raw(t *testing.T) {
	t.Parallel()
	expRawIV := binary.BigEndian.AppendUint32(nil, 0x01020304)
	expRawIV = binary.BigEndian.AppendUint64(expRawIV, 0x0b16212c37424d58)
	iv, _ := LoadIV96(expRawIV)
	rawIV := iv.Raw()
	assert.Equal(t, expRawIV, rawIV)
}

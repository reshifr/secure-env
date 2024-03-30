package crypt

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_MakeIV96(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidIVFixedLen error", func(t *testing.T) {
		t.Parallel()
		fixed := [2]byte{}
		var expIV *IV96 = nil
		expErr := ErrInvalidIVFixedLen

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
		expErr := ErrInvalidRawIVLen

		iv, err := LoadIV96(rawIV[:])
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		fixed := uint32(0x01020304)
		invocation := uint64(0x0b16212c37424d58)
		rawIV := [IV96Len]byte{}
		binary.BigEndian.PutUint32(rawIV[0:IV96FixedLen], fixed)
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
	t.Run("Serial access", func(t *testing.T) {
		t.Parallel()
		fixed := uint32(0x01020304)
		invocation := uint64(0)
		executed := uint64(1000)
		iv := &IV96{fixed: fixed, invocation: invocation}
		expIV := &IV96{fixed: fixed, invocation: invocation + executed}

		for i := invocation; i < executed; i++ {
			iv.Invoke()
		}
		assert.Equal(t, expIV, iv)
	})
	t.Run("Concurrent access", func(t *testing.T) {
		t.Parallel()
		fixed := uint32(0x01020304)
		invocation := uint64(0)
		executed := uint64(1000)
		iv := &IV96{fixed: fixed, invocation: invocation}
		expIV := &IV96{fixed: fixed, invocation: invocation + executed}

		invocations := map[uint64]struct{}{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := invocation; i < executed; i++ {
			wg.Add(1)
			go func() {
				newIV := iv.Invoke()
				mu.Lock()
				invocations[newIV.(*IV96).invocation] = struct{}{}
				mu.Unlock()
				wg.Done()
			}()
		}
		wg.Wait()
		assert.Equal(t, expIV, iv)
		assert.Equal(t, executed, uint64(len(invocations)))
	})
}

func Test_IV96_Raw(t *testing.T) {
	t.Parallel()
	fixed := uint32(0x01020304)
	invocation := uint64(0x0b16212c37424d58)
	iv := &IV96{fixed: fixed, invocation: invocation}
	expRawIV := make([]byte, IV96Len)
	binary.BigEndian.PutUint32(expRawIV[0:IV96FixedLen], fixed)
	binary.BigEndian.PutUint64(expRawIV[IV96FixedLen:IV96Len], invocation)

	rawIV := iv.Raw()
	assert.Equal(t, expRawIV, rawIV)
}

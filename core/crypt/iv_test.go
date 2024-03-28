package crypt

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_IVError_Error(t *testing.T) {
	t.Parallel()
	err := ErrIVInvalidLen
	expMsg := "ErrIVInvalidLen: invalid size of raw IV."

	msg := err.Error()
	assert.Equal(t, expMsg, msg)
}

func Test_LoadIV(t *testing.T) {
	t.Parallel()
	t.Run("Invalid size of raw IV", func(t *testing.T) {
		t.Parallel()
		rawIV := []byte{0xff, 0xff, 0xff}
		expIV := &IV{}
		expErr := ErrIVInvalidLen

		iv, err := LoadIV(rawIV)
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Valid size of raw IV", func(t *testing.T) {
		t.Parallel()
		ivId := uint32(0x01020304)
		ivInc := uint64(0x0b16212c37424d58)
		rawIV := binary.BigEndian.AppendUint32(nil, ivId)
		rawIV = binary.BigEndian.AppendUint64(rawIV, ivInc)
		expIV := &IV{id: ivId, inc: ivInc}

		iv, err := LoadIV(rawIV)
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_CreateIV(t *testing.T) {
	t.Parallel()
	ivId := uint32(0x01020304)
	ivInc := uint64(0)
	expIV := &IV{id: ivId, inc: ivInc}

	iv := CreateIV(ivId)
	assert.Equal(t, expIV, iv)
}

func Test_IV_Invoke(t *testing.T) {
	t.Parallel()
	ivId := uint32(0x01020304)
	ivInc := uint64(0)
	executed := uint64(999)
	iv := &IV{id: ivId, inc: ivInc}
	expIV := &IV{id: ivId, inc: executed}

	var wg sync.WaitGroup
	for i := ivInc; i < executed; i++ {
		wg.Add(1)
		go func() {
			iv.Invoke()
			wg.Done()
		}()
	}
	wg.Wait()
	assert.Equal(t, expIV, iv)
}

func Test_IV_Raw(t *testing.T) {
	t.Parallel()
	ivId := uint32(0x01020304)
	ivInc := uint64(0x0b16212c37424d58)
	iv := &IV{id: ivId, inc: ivInc}
	expRawIV := binary.BigEndian.AppendUint32(nil, ivId)
	expRawIV = binary.BigEndian.AppendUint64(expRawIV, ivInc)

	rawIV := iv.Raw()
	assert.Equal(t, expRawIV, rawIV)
}

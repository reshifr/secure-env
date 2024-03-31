package crypto_impl

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	"github.com/stretchr/testify/assert"
)

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
		executed := uint64(1000)
		fixed := binary.BigEndian.AppendUint32(nil, 0x01020304)
		iv, _ := MakeIV96(fixed)
		expIV, _ := MakeIV96(fixed)
		expIV.invocation = executed
		for i := iv.invocation; i < executed; i++ {
			iv.Invoke()
		}
		assert.Equal(t, expIV, iv)
	})
	t.Run("Concurrent access", func(t *testing.T) {
		t.Parallel()
		executed := uint64(1000)
		fixed := binary.BigEndian.AppendUint32(nil, 0x01020304)
		iv, _ := MakeIV96(fixed)
		expIV, _ := MakeIV96(fixed)
		expIV.invocation = executed

		invocations := map[uint64]struct{}{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := iv.invocation; i < executed; i++ {
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
	expRawIV := binary.BigEndian.AppendUint32(nil, 0x01020304)
	expRawIV = binary.BigEndian.AppendUint64(expRawIV, 0x0b16212c37424d58)
	iv, _ := LoadIV96(expRawIV)
	rawIV := iv.Raw()
	assert.Equal(t, expRawIV, rawIV)
}

package crypto_test

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"

	cimpl "github.com/reshifr/secure-env/core/crypto/impl"
	"github.com/stretchr/testify/assert"
)

func Test_IV96_Invoke(t *testing.T) {
	t.Parallel()
	executed := uint64(1000)
	t.Run("Concurrent access", func(t *testing.T) {
		t.Parallel()
		fixed := binary.BigEndian.AppendUint32(nil, 0x01020304)
		rawIV := bytes.Clone(fixed)
		rawIV = binary.BigEndian.AppendUint64(rawIV, executed)
		iv, _ := cimpl.MakeIV96(fixed)
		expIV, _ := cimpl.LoadIV96(rawIV)

		rawIVs := map[[cimpl.IV96Len]byte]struct{}{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := 0; i < int(executed); i++ {
			wg.Add(1)
			go func() {
				newIV := iv.Invoke()
				mu.Lock()
				vRawIV := [cimpl.IV96Len]byte{}
				copy(vRawIV[:], newIV.Raw())
				rawIVs[vRawIV] = struct{}{}
				mu.Unlock()
				wg.Done()
			}()
		}
		wg.Wait()
		assert.Equal(t, expIV, iv)
		assert.Equal(t, executed, uint64(len(rawIVs)))
	})
	t.Run("Invocation overflow", func(t *testing.T) {
		t.Parallel()
		rawIV := [cimpl.IV96Len]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0x00,
		}
		iv, _ := cimpl.LoadIV96(rawIV[:])
		rawIVs := map[[cimpl.IV96Len]byte]struct{}{}
		for i := 0; i < int(executed); i++ {
			newIV := iv.Invoke()
			vRawIV := [cimpl.IV96Len]byte{}
			copy(vRawIV[:], newIV.Raw())
			rawIVs[vRawIV] = struct{}{}
		}
		assert.Equal(t, executed, uint64(len(rawIVs)))
	})
}

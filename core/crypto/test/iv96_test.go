package crypto_test

import (
	"encoding/hex"
	"sync"
	"testing"

	cimpl "github.com/reshifr/secure-env/core/crypto/impl"
	"github.com/stretchr/testify/assert"
)

func Test_IV96_Invoke(t *testing.T) {
	t.Parallel()
	const executed = 1000

	t.Run("Concurrent access", func(t *testing.T) {
		t.Parallel()
		rawIV, _ := hex.DecodeString("10101010fffffffffffffff0")
		expInvokedRawIV, _ := hex.DecodeString("1010101100000000000003d8")

		iv, _ := cimpl.LoadIV96(rawIV)
		rawIVs := map[[cimpl.IV96Len]byte]struct{}{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := 0; i < executed-1; i++ {
			wg.Add(1)
			go func() {
				invokedRawIV := iv.Invoke()
				mu.Lock()
				vInvokedRawIV := [cimpl.IV96Len]byte{}
				copy(vInvokedRawIV[:], invokedRawIV)
				rawIVs[vInvokedRawIV] = struct{}{}
				mu.Unlock()
				wg.Done()
			}()
		}
		wg.Wait()

		invokedRawIV := iv.Invoke()
		vInvokedRawIV := [cimpl.IV96Len]byte{}
		copy(vInvokedRawIV[:], invokedRawIV)
		rawIVs[vInvokedRawIV] = struct{}{}
		assert.Equal(t, expInvokedRawIV, invokedRawIV)
		assert.Equal(t, executed, len(rawIVs))
	})
	t.Run("Invocation overflow", func(t *testing.T) {
		t.Parallel()
		rawIV, _ := hex.DecodeString("ffffffffffffffffffffff00")
		iv, _ := cimpl.LoadIV96(rawIV)

		rawIVs := map[[cimpl.IV96Len]byte]struct{}{}
		for i := 0; i < executed; i++ {
			invokedRawIV := iv.Invoke()
			vInvokedRawIV := [cimpl.IV96Len]byte{}
			copy(vInvokedRawIV[:], invokedRawIV)
			rawIVs[vInvokedRawIV] = struct{}{}
		}
		assert.Equal(t, executed, len(rawIVs))
	})
}

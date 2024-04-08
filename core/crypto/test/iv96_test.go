package crypto_test

import (
	"encoding/binary"
	"sync"
	"testing"

	cimpl "github.com/reshifr/secure-env/core/crypto/impl"
	"github.com/stretchr/testify/assert"
)

func Test_IV96_Invoke_Concurrently(t *testing.T) {
	t.Parallel()
	fixed := binary.BigEndian.AppendUint32(nil, 0x01020304)
	iv, _ := cimpl.MakeIV96(fixed)
	executed := uint64(1000)
	rawIV := binary.BigEndian.AppendUint32(nil, 0x01020304)
	rawIV = binary.BigEndian.AppendUint64(rawIV, executed)
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
}

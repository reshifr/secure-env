package crypto_impl

import (
	"encoding/hex"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	"github.com/stretchr/testify/assert"
)

func Test_LoadGlobalIV96(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidIVLen error", func(t *testing.T) {
		t.Parallel()
		rawIV := make([]byte, 8)
		var expIV *GlobalIV96 = nil
		const expErr = crypto.ErrInvalidIVLen

		iv, err := LoadGlobalIV96(rawIV)
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		const subv0 = uint32(0x11111111)
		const subv1 = uint64(0x2222222222222222)
		rawIV, _ := hex.DecodeString("111111112222222222222222")
		expIV := &GlobalIV96{subv0: subv0, subv1: subv1}

		iv, err := LoadGlobalIV96(rawIV)
		assert.Equal(t, expIV, iv)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_GlobalIV96_Len(t *testing.T) {
	t.Parallel()
	const expIVLen = uint32(GlobalIV96Len)

	iv := &GlobalIV96{}
	ivLen := iv.Len()
	assert.Equal(t, expIVLen, ivLen)
}

func Test_GlobalIV96_Invoke(t *testing.T) {
	t.Parallel()
	const executed = 1000
	rawIV, _ := hex.DecodeString("10101010fffffffffffffff0")
	expInvokedRawIV, _ := hex.DecodeString("1010101100000000000003d8")

	var invokedRawIV []byte
	iv, _ := LoadGlobalIV96(rawIV)
	for i := 0; i < int(executed); i++ {
		invokedRawIV = iv.Invoke()
	}
	assert.Equal(t, expInvokedRawIV, invokedRawIV)
}

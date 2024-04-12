package crypto_impl

import (
	"encoding/binary"
	"sync"

	"github.com/reshifr/secure-env/core/crypto"
)

const (
	GlobalIV96Len = 12
)

type GlobalIV96 struct {
	mu    sync.Mutex
	subv0 uint32
	subv1 uint64
}

func LoadGlobalIV96(rawIV []byte) (*GlobalIV96, error) {
	if len(rawIV) != GlobalIV96Len {
		return nil, crypto.ErrInvalidIVLen
	}
	iv := &GlobalIV96{
		subv0: binary.BigEndian.Uint32(rawIV),
		subv1: binary.BigEndian.Uint64(rawIV[4:]),
	}
	return iv, nil
}

func (*GlobalIV96) Len() uint32 {
	return GlobalIV96Len
}

func (iv *GlobalIV96) Invoke() []byte {
	iv.mu.Lock()
	if iv.subv1 == 0xffffffffffffffff {
		iv.subv0++
	}
	iv.subv1++
	raw := make([]byte, GlobalIV96Len)
	binary.BigEndian.PutUint32(raw, iv.subv0)
	binary.BigEndian.PutUint64(raw[4:], iv.subv1)
	iv.mu.Unlock()
	return raw
}

package crypto_impl

import (
	"encoding/binary"
	"sync"

	"github.com/reshifr/secure-env/core/crypto"
)

const (
	IV96Len = 12
)

type IV96 struct {
	mu    sync.Mutex
	subv0 uint32
	subv1 uint64
}

func LoadIV96(rawIV []byte) (*IV96, error) {
	if len(rawIV) != IV96Len {
		return nil, crypto.ErrInvalidIVLen
	}
	iv := &IV96{
		subv0: binary.BigEndian.Uint32(rawIV),
		subv1: binary.BigEndian.Uint64(rawIV[4:]),
	}
	return iv, nil
}

func (*IV96) Len() uint32 {
	return IV96Len
}

func (iv *IV96) Invoke() []byte {
	iv.mu.Lock()
	if iv.subv1 == 0xffffffffffffffff {
		iv.subv0++
	}
	iv.subv1++
	raw := make([]byte, IV96Len)
	binary.BigEndian.PutUint32(raw, iv.subv0)
	binary.BigEndian.PutUint64(raw[4:], iv.subv1)
	iv.mu.Unlock()
	return raw
}

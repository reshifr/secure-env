package crypt

import (
	"encoding/binary"
	"sync/atomic"

	"github.com/reshifr/secure-env/core/crypt"
)

const (
	IV96Len           = 12
	IV96FixedLen      = 4
	IV96InvocationLen = 8
)

type IV96 struct {
	fixed      uint32
	invocation uint64
}

func MakeIV96(fixed []byte) (*IV96, error) {
	if len(fixed) != IV96FixedLen {
		return nil, crypt.ErrInvalidIVFixedLen
	}
	encFixed := binary.BigEndian.Uint32(fixed)
	iv := &IV96{fixed: encFixed, invocation: 0}
	return iv, nil
}

func LoadIV96(rawIV []byte) (*IV96, error) {
	if len(rawIV) != IV96Len {
		return nil, crypt.ErrInvalidRawIVLen
	}
	iv := &IV96{
		fixed:      binary.BigEndian.Uint32(rawIV[:IV96FixedLen]),
		invocation: binary.BigEndian.Uint64(rawIV[IV96FixedLen:IV96Len]),
	}
	return iv, nil
}

func (*IV96) Len() uint32 {
	return IV96Len
}

func (*IV96) FixedLen() uint32 {
	return IV96FixedLen
}

func (iv *IV96) Invoke() crypt.CipherIV {
	return &IV96{
		fixed:      iv.fixed,
		invocation: atomic.AddUint64(&iv.invocation, 1),
	}
}

func (iv *IV96) Raw() []byte {
	rawIV := make([]byte, IV96Len)
	binary.BigEndian.PutUint32(rawIV[:IV96FixedLen], iv.fixed)
	binary.BigEndian.PutUint64(rawIV[IV96FixedLen:IV96Len], iv.invocation)
	return rawIV
}

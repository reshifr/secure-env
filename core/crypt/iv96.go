package crypt

import (
	"encoding/binary"
	"sync/atomic"
)

const (
	IV96Len           int = 12
	IV96FixedLen      int = 4
	IV96InvocationLen int = 8
)

type IV96 struct {
	fixed      uint32
	invocation uint64
}

func MakeIV96(fixed []byte) (*IV96, error) {
	if len(fixed) != IV96FixedLen {
		return nil, ErrInvalidIVFixedLen
	}
	encFixed := binary.BigEndian.Uint32(fixed)
	iv := &IV96{fixed: encFixed, invocation: 0}
	return iv, nil
}

func LoadIV96(rawIV []byte) (*IV96, error) {
	if len(rawIV) != IV96Len {
		return nil, ErrInvalidRawIVLen
	}
	iv := &IV96{
		fixed:      binary.BigEndian.Uint32(rawIV[0:IV96FixedLen]),
		invocation: binary.BigEndian.Uint64(rawIV[IV96FixedLen:IV96Len]),
	}
	return iv, nil
}

func (*IV96) Len() int {
	return IV96Len
}

func (*IV96) FixedLen() int {
	return IV96FixedLen
}

func (iv *IV96) Invoke() ICipherIV {
	return &IV96{
		fixed:      iv.fixed,
		invocation: atomic.AddUint64(&iv.invocation, 1),
	}
}

func (iv *IV96) Raw() []byte {
	rawIV := [IV96Len]byte{}
	binary.BigEndian.PutUint32(rawIV[0:IV96FixedLen], iv.fixed)
	binary.BigEndian.PutUint64(rawIV[IV96FixedLen:IV96Len], iv.invocation)
	return rawIV[:]
}

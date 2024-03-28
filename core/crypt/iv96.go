package crypt

import (
	"encoding/binary"
	"sync/atomic"
)

type IV96 struct {
	id  uint32
	inc uint64
}

func LoadIV96(rawIV []byte) (*IV96, error) {
	iv := &IV96{}
	if len(rawIV) != 12 {
		return iv, ErrIVInvalidLen
	}
	iv.id = binary.BigEndian.Uint32(rawIV[0:4])
	iv.inc = binary.BigEndian.Uint64(rawIV[4:12])
	return iv, nil
}

func MakeIV96(id uint32) *IV96 {
	iv := &IV96{id: id, inc: 0}
	return iv
}

func (iv *IV96) Invoke() {
	atomic.AddUint64(&iv.inc, 1)
}

func (iv *IV96) Raw() []byte {
	var rawIV [12]byte
	binary.BigEndian.PutUint32(rawIV[0:4], iv.id)
	binary.BigEndian.PutUint64(rawIV[4:12], iv.inc)
	return rawIV[:]
}

func (iv *IV96) Len() int {
	return 12
}

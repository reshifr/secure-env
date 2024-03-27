package crypt

import (
	"encoding/binary"
	"sync/atomic"
)

type IV struct {
	id  uint32
	inc uint64
}

func LoadIV(rawIV []byte) (*IV, error) {
	iv := &IV{}
	if len(rawIV) != 12 {
		return iv, ErrIVInvalidLen
	}
	iv.id = binary.BigEndian.Uint32(rawIV[0:4])
	iv.inc = binary.BigEndian.Uint64(rawIV[4:12])
	return iv, nil
}

func CreateIV(id uint32) *IV {
	iv := &IV{id: id, inc: 0}
	return iv
}

func (iv *IV) Invoke() {
	atomic.AddUint64(&iv.inc, 1)
}

func (iv *IV) Raw() []byte {
	var rawIV [12]byte
	binary.BigEndian.PutUint32(rawIV[0:4], iv.id)
	binary.BigEndian.PutUint64(rawIV[4:12], iv.inc)
	return rawIV[:]
}

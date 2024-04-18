package crypto_impl

import (
	"github.com/reshifr/secure-env/core/crypto"
)

type StdRNG struct {
	fn FnStdRNG
}

type FnStdRNG struct {
	Read func(b []byte) (n int, err error)
}

func NewStdRNG(fn FnStdRNG) StdRNG {
	return StdRNG{fn: fn}
}

func (rng StdRNG) Block(blockLen int) ([]byte, error) {
	block := make([]byte, blockLen)
	if _, err := rng.fn.Read(block); err != nil {
		return nil, crypto.ErrReadEntropyFailed
	}
	return block, nil
}

func (rng StdRNG) Read(block []byte) error {
	if _, err := rng.fn.Read(block); err != nil {
		return crypto.ErrReadEntropyFailed
	}
	return nil
}

package crypt

import (
	"github.com/reshifr/secure-env/core/crypt"
)

type AutoRNG struct {
	fnCSPRNG crypt.FnCSPRNG
}

func NewAutoRNG(fnCSPRNG crypt.FnCSPRNG) AutoRNG {
	return AutoRNG{fnCSPRNG: fnCSPRNG}
}

func (rng AutoRNG) Make(blockLen int) ([]byte, error) {
	block := make([]byte, blockLen)
	if _, err := rng.fnCSPRNG.Read(block); err != nil {
		return nil, crypt.ErrReadEntropyFailed
	}
	return block, nil
}

func (rng AutoRNG) Read(block []byte) error {
	if _, err := rng.fnCSPRNG.Read(block); err != nil {
		return crypt.ErrReadEntropyFailed
	}
	return nil
}

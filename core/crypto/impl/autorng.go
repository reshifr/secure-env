package crypto_impl

import (
	"github.com/reshifr/secure-env/core/crypto"
)

type AutoRNG struct {
	fnCSPRNG crypto.FnCSPRNG
}

func NewAutoRNG(fnCSPRNG crypto.FnCSPRNG) AutoRNG {
	return AutoRNG{fnCSPRNG: fnCSPRNG}
}

func (rng AutoRNG) Block(blockLen int) ([]byte, error) {
	block := make([]byte, blockLen)
	if _, err := rng.fnCSPRNG.Read(block); err != nil {
		return nil, crypto.ErrReadEntropyFailed
	}
	return block, nil
}

func (rng AutoRNG) Read(block []byte) error {
	if _, err := rng.fnCSPRNG.Read(block); err != nil {
		return crypto.ErrReadEntropyFailed
	}
	return nil
}

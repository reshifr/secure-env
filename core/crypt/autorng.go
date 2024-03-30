package crypt

type AutoRNG struct {
	fnCSPRNG FnCSPRNG
}

func NewAutoRNG(fnCSPRNG FnCSPRNG) AutoRNG {
	return AutoRNG{fnCSPRNG: fnCSPRNG}
}

func (rng AutoRNG) Make(blockLen int) ([]byte, error) {
	block := make([]byte, blockLen)
	if _, err := rng.fnCSPRNG.Read(block); err != nil {
		return nil, ErrReadEntropyFailed
	}
	return block, nil
}

func (rng AutoRNG) Read(block []byte) error {
	if _, err := rng.fnCSPRNG.Read(block); err != nil {
		return ErrReadEntropyFailed
	}
	return nil
}

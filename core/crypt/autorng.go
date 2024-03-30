package crypt

type AutoRNG struct {
	fnCSPRNG FnCSPRNG
}

func OpenAutoRNG(fnCSPRNG FnCSPRNG) *AutoRNG {
	return &AutoRNG{fnCSPRNG: fnCSPRNG}
}

func (csprng *AutoRNG) Make(blockLen int) ([]byte, error) {
	block := make([]byte, blockLen)
	if _, err := csprng.fnCSPRNG.Read(block); err != nil {
		return nil, ErrReadEntropyFailed
	}
	return block, nil
}

func (csprng *AutoRNG) Read(block []byte) error {
	if _, err := csprng.fnCSPRNG.Read(block); err != nil {
		return ErrReadEntropyFailed
	}
	return nil
}

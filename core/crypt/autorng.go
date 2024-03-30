package crypt

type AutoRNG struct {
	csprngFn FnCSPRNG
}

func OpenAutoRNG(csprngFn FnCSPRNG) *AutoRNG {
	return &AutoRNG{csprngFn: csprngFn}
}

func (csprng *AutoRNG) Make(blockLen int) ([]byte, error) {
	block := make([]byte, blockLen)
	if _, err := csprng.csprngFn.Read(block); err != nil {
		return nil, ErrReadEntropyFailed
	}
	return block, nil
}

func (csprng *AutoRNG) Read(block []byte) error {
	if _, err := csprng.csprngFn.Read(block); err != nil {
		return ErrReadEntropyFailed
	}
	return nil
}

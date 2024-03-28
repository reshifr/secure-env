package crypt

type AutoRNG struct {
	csprngFn FnCSPRNG
}

func NewAutoRNG(csprngFn FnCSPRNG) *AutoRNG {
	return &AutoRNG{csprngFn: csprngFn}
}

func (csprng *AutoRNG) Read(block []byte) error {
	_, err := csprng.csprngFn.Read(block)
	if err != nil {
		return ErrCSPRNGRead
	}
	return nil
}

func (csprng *AutoRNG) Make(blockLen int) ([]byte, error) {
	b := make([]byte, blockLen)
	_, err := csprng.csprngFn.Read(b)
	if err != nil {
		return b, ErrCSPRNGRead
	}
	return b, nil
}

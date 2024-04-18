package crypto

type RNGError int

const (
	ErrReadEntropyFailed RNGError = iota + 1
)

func (err RNGError) Error() string {
	switch err {
	case ErrReadEntropyFailed:
		return "ErrReadEntropyFailed: " +
			"Failed to read a random value from the entropy sources."
	default:
		return "Error: unknown."
	}
}

type RNG interface {
	Block(blockLen int) (block []byte, err error)
	Read(block []byte) (err error)
}

package crypto

type CSPRNGError int

const (
	ErrReadEntropyFailed CSPRNGError = iota + 1
)

func (err CSPRNGError) Error() string {
	switch err {
	case ErrReadEntropyFailed:
		return "ErrReadEntropyFailed: " +
			"Failed to read a random value from the entropy sources."
	default:
		return "Error: unknown."
	}
}

type CSPRNG interface {
	Block(blockLen int) (block []byte, err error)
	Read(block []byte) (err error)
}

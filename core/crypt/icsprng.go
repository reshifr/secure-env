package crypt

type CSPRNGError int

const (
	ErrCSPRNGRead CSPRNGError = iota + 1
)

func (err CSPRNGError) Error() string {
	return "ErrCSPRNGRead: " +
		"Failed to read a random value from the entropy sources."
}

type FnCSPRNG struct {
	Read func(b []byte) (n int, err error)
}

type ICSPRNG interface {
	Read(block []byte) (err error)
	Make(blockLen int) (block []byte, err error)
}

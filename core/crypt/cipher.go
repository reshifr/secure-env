package crypt

type CipherError int

const (
	ErrCipherInvalidKeyLen CipherError = iota + 1
)

func (err CipherError) Error() string {
	return "ErrCipherInvalidKeyLen: " +
		"Failed to read a random value from the entropy sources."
}

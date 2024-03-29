package crypt

type CipherError int

const (
	ErrInvalidKeyLen CipherError = iota + 1
	ErrInvalidIVLen
)

func (err CipherError) Error() string {
	return "ErrInvalidKeyLen: invalid key size."
}

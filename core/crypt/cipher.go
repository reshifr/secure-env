package crypt

// Error
type CipherError int

const (
	ErrInvalidIVLen CipherError = iota + 1
	ErrInvalidRawIVLen
	ErrInvalidKeyLen
)

func (err CipherError) Error() string {
	switch err {
	case ErrInvalidIVLen:
		return "ErrInvalidIVLen: invalid IV size."
	case ErrInvalidRawIVLen:
		return "ErrInvalidRawIVLen: invalid raw IV size."
	default:
		return "ErrInvalidKeyLen: invalid key size."
	}
}

type ICipherIV interface {
	Invoke()
	Raw() (rawIV []byte)
	Len() (ivLen int)
}

type ICipherBuf interface {
	Add()
	Salt()
	Ciphertext()
}

// Interface
type ICipher interface {
	Seal(iv ICipherIV, passphrase string,
		plaintext []byte) (cipherBuf *ICipherBuf, err error)
}

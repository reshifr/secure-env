package crypto

type CipherError int

const (
	ErrInvalidIVLen CipherError = iota + 1
	ErrInvalidKeyLen
	ErrInvalidBufLayout
)

func (err CipherError) Error() string {
	switch err {
	case ErrInvalidIVLen:
		return "ErrInvalidIVLen: invalid IV length."
	case ErrInvalidKeyLen:
		return "ErrInvalidKeyLen: invalid key length."
	case ErrInvalidBufLayout:
		return "ErrInvalidBufLayout: the buffer structure cannot be read."
	default:
		return "Error: unknown."
	}
}

type AEError int

const (
	ErrAuthFailed AEError = iota + 1
)

func (err AEError) Error() string {
	switch err {
	case ErrAuthFailed:
		return "ErrAuthFailed: failed to decrypt the data."
	default:
		return "Error: unknown."
	}
}

type IV interface {
	Len() (ivLen uint32)
	Invoke() (invokedRawIV []byte)
}

type AE interface {
	KeyLen() (keyLen uint32)
	Seal(iv IV, key []byte, plaintext []byte) (buf []byte, err error)
	Open(key []byte, buf []byte) (ciphertext []byte, err error)
}

package crypt

// Error
type CipherError int

const (
	ErrInvalidIVLen CipherError = iota + 1
	ErrInvalidIVFixedLen
	ErrInvalidRawIVLen
	ErrInvalidAddLen
	ErrInvalidKeyLen
	ErrInvalidSaltLen
	ErrInvalidBufferStructure
)

func (err CipherError) Error() string {
	switch err {
	case ErrInvalidIVLen:
		return "ErrInvalidIVLen: invalid IV size."
	case ErrInvalidIVFixedLen:
		return "ErrInvalidIVFixedLen: invalid IV fixed size."
	case ErrInvalidRawIVLen:
		return "ErrInvalidRawIVLen: invalid raw IV size."
	default:
		return "ErrInvalidKeyLen: invalid key size."
	}
}

type ICipherIV interface {
	Len() (ivLen int)
	FixedLen() (fixedLen int)
	Invoke() (newIV ICipherIV)
	Raw() (rawIV []byte)
}

type ICipherBuf interface {
	Add()
	Salt()
	Ciphertext()
}

// // Interface
// type ICipher interface {
// 	AddLen() (addLen int)
// 	KeyLen() (keyLen int)
// 	SaltLen() (saltLen int)
// 	Seal(iv ICipherIV, passphrase string,
// 		plaintext []byte) (cipherBuf *ICipherBuf, err error)
// }

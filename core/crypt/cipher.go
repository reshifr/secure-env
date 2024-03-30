package crypt

type CipherError int

const (
	ErrInvalidIVLen CipherError = iota + 1
	ErrInvalidIVFixedLen
	ErrInvalidRawIVLen
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
	Len() (ivLen uint32)
	FixedLen() (fixedLen uint32)
	Invoke() (newIV ICipherIV)
	Raw() (rawIV []byte)
}

type ICipherBuf interface {
	Add() (add []byte)
	Salt() (salt []byte)
	Ciphertext() (ciphertext []byte)
	Block() (block []byte)
}

// // Interface
// type ICipher interface {
// 	AddLen() (addLen int)
// 	KeyLen() (keyLen int)
// 	SaltLen() (saltLen int)
// 	Seal(iv ICipherIV, passphrase string,
// 		plaintext []byte) (cipherBuf *ICipherBuf, err error)
// }

package crypt

type CipherError int

const (
	ErrInvalidIVLen CipherError = iota + 1
	ErrInvalidIVFixedLen
	ErrInvalidRawIVLen
	ErrInvalidKeyLen
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
	Ciphertext() (ciphertext []byte)
	Block() (block []byte)
}

type ICipher interface {
	KeyLen() (keyLen uint32)
	Seal(iv ICipherIV, key []byte,
		plaintext []byte) (cipherbuf ICipherBuf, err error)
}

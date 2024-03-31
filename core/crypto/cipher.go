package crypto

type CipherError int

const (
	ErrInvalidIVLen CipherError = iota + 1
	ErrInvalidIVFixedLen
	ErrInvalidRawIVLen
	ErrInvalidKeyLen
	ErrInvalidCipherOpenFailed
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

type CipherIV interface {
	Len() (ivLen uint32)
	FixedLen() (fixedLen uint32)
	Invoke() (newIV CipherIV)
	Raw() (rawIV []byte)
}

type CipherBuf interface {
	RawIV() (rawIV []byte)
	Add() (add []byte)
	Ciphertext() (ciphertext []byte)
	Block() (block []byte)
}

type Cipher interface {
	KeyLen() (keyLen uint32)
	IV(fixed []byte) (iv CipherIV, err error)
	RandomIV() (iv CipherIV, err error)
	Seal(iv CipherIV, key []byte,
		plaintext []byte) (cipherbuf CipherBuf, err error)
	Open(iv CipherIV, key []byte,
		cipherbuf CipherBuf) (ciphertext []byte, err error)
}

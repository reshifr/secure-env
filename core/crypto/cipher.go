package crypto

type CipherError int

const (
	ErrInvalidIVLen CipherError = iota + 1
	ErrInvalidIVFixedLen
	ErrInvalidRawIVLen
	ErrInvalidKeyLen
	ErrInvalidBuffer
	ErrCipherAuthFailed
)

func (err CipherError) Error() string {
	switch err {
	case ErrInvalidIVLen:
		return "ErrInvalidIVLen: invalid IV length."
	case ErrInvalidIVFixedLen:
		return "ErrInvalidIVFixedLen: invalid IV 'fixed' length."
	case ErrInvalidRawIVLen:
		return "ErrInvalidRawIVLen: invalid raw IV length."
	case ErrInvalidKeyLen:
		return "ErrInvalidKeyLen: invalid key length."
	case ErrInvalidBuffer:
		return "ErrInvalidBuffer: the buffer structure cannot be read."
	case ErrCipherAuthFailed:
		return "ErrCipherAuthFailed: failed to decrypt the data."
	default:
		return "Error: unknown."
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
	Ciphertext() (ciphertext []byte)
	Raw() (rawBuf []byte)
}

type Cipher interface {
	IVLen() (ivLen uint32)
	IVFixedLen() (fixedLen uint32)
	KeyLen() (keyLen uint32)
	MakeIV(fixed []byte) (iv CipherIV, err error)
	LoadIV(rawIV []byte) (iv CipherIV, err error)
	Encrypt(iv CipherIV, key []byte, plaintext []byte) (buf CipherBuf, err error)
	Decrypt(key []byte, buf CipherBuf) (plaintext []byte, err error)
}

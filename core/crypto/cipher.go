package crypto

type CipherError int

const (
	ErrInvalidIVLen CipherError = iota + 1
	ErrInvalidKeyLen
	ErrInvalidBufferLayout
	ErrCipherAuthFailed
)

func (err CipherError) Error() string {
	switch err {
	case ErrInvalidIVLen:
		return "ErrInvalidIVLen: invalid IV length."
	case ErrInvalidKeyLen:
		return "ErrInvalidKeyLen: invalid key length."
	case ErrInvalidBufferLayout:
		return "ErrInvalidBufferLayout: the buffer structure cannot be read."
	case ErrCipherAuthFailed:
		return "ErrCipherAuthFailed: failed to decrypt the data."
	default:
		return "Error: unknown."
	}
}

type CipherIV interface {
	Len() (ivLen uint32)
	Invoke() (invokedRawIV []byte)
}

type CipherBuf interface {
	Len() (bufLen int)
	RawIV() (rawIV []byte)
	Ciphertext() (ciphertext []byte)
	Raw() (rawBuf []byte)
}

type Cipher interface {
	KeyLen() (keyLen uint32)
	MakeBuf(rawIV []byte, ciphertext []byte) (buf CipherBuf, err error)
	LoadBuf(rawBuf []byte) (buf CipherBuf, err error)
	Seal(iv CipherIV, key []byte, plaintext []byte) (buf CipherBuf, err error)
	Open(key []byte, buf CipherBuf) (ciphertext []byte, err error)
}

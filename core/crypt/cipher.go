package crypt

type CipherError int

const (
	ErrInvalidKeyLen CipherError = iota + 1
	ErrInvalidIVLen
)

func (err CipherError) Error() string {
	return "ErrInvalidKeyLen: invalid key size."
}

type ICipher interface {
	KeyLen() uint32
	Encrypt(iv IIV, passphrase string,
		plaintext []byte) (cipherBuf *CipherBuf, err error)
}

type CipherBuf struct {
	Add        []byte
	Salt       []byte
	Ciphertext []byte
}

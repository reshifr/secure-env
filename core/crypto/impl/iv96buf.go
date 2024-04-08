package crypto_impl

import (
	"github.com/reshifr/secure-env/core/crypto"
)

type IV96Buf struct {
	rawIV      []byte
	ciphertext []byte
}

func MakeIV96Buf(rawIV []byte, ciphertext []byte) (*IV96Buf, error) {
	if len(rawIV) != IV96Len {
		return nil, crypto.ErrInvalidRawIVLen
	}
	buf := &IV96Buf{rawIV: rawIV, ciphertext: ciphertext}
	return buf, nil
}

func LoadIV96Buf(rawBuf []byte) (*IV96Buf, error) {
	if len(rawBuf) < IV96Len {
		return nil, crypto.ErrInvalidBufferLayout
	}
	buf := &IV96Buf{rawIV: rawBuf[:IV96Len], ciphertext: rawBuf[IV96Len:]}
	return buf, nil
}

func (buf *IV96Buf) Len() uint64 {
	return IV96Len + uint64(len(buf.ciphertext))
}

func (buf *IV96Buf) RawIV() []byte {
	return buf.rawIV
}

func (buf *IV96Buf) Ciphertext() []byte {
	return buf.ciphertext
}

func (buf *IV96Buf) Raw() []byte {
	rawBuf := make([]byte, IV96Len+len(buf.ciphertext))
	copy(rawBuf[:IV96Len], buf.rawIV)
	copy(rawBuf[IV96Len:], buf.ciphertext)
	return rawBuf
}

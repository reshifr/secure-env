package crypto_impl

import (
	"github.com/reshifr/secure-env/core/crypto"
)

const (
	AE96BufIVLen = 12
)

type AE96Buf struct {
	rawIV      []byte
	ciphertext []byte
}

func MakeAE96Buf(rawIV []byte, ciphertext []byte) (*AE96Buf, error) {
	if len(rawIV) != AE96BufIVLen {
		return nil, crypto.ErrInvalidIVLen
	}
	buf := &AE96Buf{rawIV: rawIV, ciphertext: ciphertext}
	return buf, nil
}

func LoadAE96Buf(rawBuf []byte) (*AE96Buf, error) {
	if len(rawBuf) < AE96BufIVLen {
		return nil, crypto.ErrInvalidBufferLayout
	}
	buf := &AE96Buf{
		rawIV:      rawBuf[:AE96BufIVLen],
		ciphertext: rawBuf[AE96BufIVLen:],
	}
	return buf, nil
}

func (buf *AE96Buf) Len() int {
	return AE96BufIVLen + len(buf.ciphertext)
}

func (buf *AE96Buf) RawIV() []byte {
	return buf.rawIV
}

func (buf *AE96Buf) Ciphertext() []byte {
	return buf.ciphertext
}

func (buf *AE96Buf) Raw() []byte {
	raw := make([]byte, buf.Len())
	copy(raw, buf.rawIV)
	copy(raw[AE96BufIVLen:], buf.ciphertext)
	return raw
}

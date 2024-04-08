package crypto_impl

import (
	"github.com/reshifr/secure-env/core/crypto"
)

type ChaCha20Poly1305Buf struct {
	block []byte
}

func MakeChaCha20Poly1305Buf(rawIV []byte,
	ad []byte, ciphertext []byte) (*ChaCha20Poly1305Buf, error) {
	if len(rawIV) != IV96Len {
		return nil, crypto.ErrInvalidRawIVLen
	}
	if len(ad) != ChaCha20Poly1305ADLen {
		return nil, crypto.ErrInvalidADLen
	}
	block := make([]byte, IV96Len+ChaCha20Poly1305ADLen+len(ciphertext))
	copy(block[:], rawIV)
	copy(block[IV96Len:], ad[:])
	copy(block[IV96Len+ChaCha20Poly1305ADLen:], ciphertext)
	buf := &ChaCha20Poly1305Buf{block: block}
	return buf, nil
}

func LoadChaCha20Poly1305Buf(block []byte) (*ChaCha20Poly1305Buf, error) {
	if len(block) < IV96Len+ChaCha20Poly1305ADLen {
		return nil, crypto.ErrInvalidBuffer
	}
	buf := &ChaCha20Poly1305Buf{block: block}
	return buf, nil
}

func (buf *ChaCha20Poly1305Buf) RawIV() []byte {
	return buf.block[:IV96Len]
}

func (buf *ChaCha20Poly1305Buf) AD() []byte {
	return buf.block[IV96Len : ChaCha20Poly1305ADLen+IV96Len]
}

func (buf *ChaCha20Poly1305Buf) Ciphertext() []byte {
	return buf.block[ChaCha20Poly1305ADLen+IV96Len:]
}

func (buf *ChaCha20Poly1305Buf) Block() []byte {
	return buf.block
}

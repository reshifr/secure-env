package crypt

import (
	"github.com/reshifr/secure-env/core/crypt"
)

type ChaCha20Poly1305Buf struct {
	block []byte
}

func MakeChaCha20Poly1305Buf(iv crypt.CipherIV, add [ChaCha20Poly1305AddLen]byte,
	ciphertext []byte) (*ChaCha20Poly1305Buf, error) {
	if iv.Len() != IV96Len {
		return nil, crypt.ErrInvalidIVLen
	}
	rawIV := iv.Raw()
	block := []byte{}
	block = append(block, rawIV...)
	block = append(block, add[:]...)
	block = append(block, ciphertext...)
	buf := &ChaCha20Poly1305Buf{block: block}
	return buf, nil
}

func LoadChaCha20Poly1305Buf(block []byte) (*ChaCha20Poly1305Buf, error) {
	if len(block) < ChaCha20Poly1305AddLen {
		return nil, crypt.ErrInvalidBufferStructure
	}
	buf := &ChaCha20Poly1305Buf{block: block}
	return buf, nil
}

func (buf *ChaCha20Poly1305Buf) IV() []byte {
	return buf.block[:IV96Len]
}

func (buf *ChaCha20Poly1305Buf) Add() []byte {
	return buf.block[IV96Len : ChaCha20Poly1305AddLen+IV96Len]
}

func (buf *ChaCha20Poly1305Buf) Ciphertext() []byte {
	return buf.block[ChaCha20Poly1305AddLen+IV96Len:]
}

func (buf *ChaCha20Poly1305Buf) Block() []byte {
	return buf.block
}

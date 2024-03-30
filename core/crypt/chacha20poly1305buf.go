package crypt

type ChaCha20Poly1305Buf struct {
	block []byte
}

func MakeChaCha20Poly1305Buf(add [ChaCha20Poly1305AddLen]byte,
	ciphertext []byte) *ChaCha20Poly1305Buf {
	block := []byte{}
	block = append(block, add[:]...)
	block = append(block, ciphertext...)
	buf := &ChaCha20Poly1305Buf{block: block}
	return buf
}

func LoadChaCha20Poly1305Buf(block []byte) (*ChaCha20Poly1305Buf, error) {
	if len(block) < ChaCha20Poly1305AddLen {
		return nil, ErrInvalidBufferStructure
	}
	buf := &ChaCha20Poly1305Buf{block: block}
	return buf, nil
}

func (buf *ChaCha20Poly1305Buf) Add() []byte {
	return buf.block[:ChaCha20Poly1305AddLen]
}

func (buf *ChaCha20Poly1305Buf) Ciphertext() []byte {
	return buf.block[ChaCha20Poly1305AddLen:]
}

func (buf *ChaCha20Poly1305Buf) Block() []byte {
	return buf.block
}

package crypt

type ChaCha20Poly1305Buf struct {
	block []byte
}

func MakeChaCha20Poly1305Buf(add []byte,
	salt []byte, ciphertext []byte) (*ChaCha20Poly1305Buf, error) {
	if len(add) != ChaCha20Poly1305AddLen {
		return nil, ErrInvalidAddLen
	}
	if len(salt) != ChaCha20Poly1305SaltLen {
		return nil, ErrInvalidSaltLen
	}
	block := []byte{}
	block = append(block, add...)
	block = append(block, salt...)
	block = append(block, ciphertext...)
	buf := &ChaCha20Poly1305Buf{block: block}
	return buf, nil
}

func LoadChaCha20Poly1305Buf(block []byte) (*ChaCha20Poly1305Buf, error) {
	if len(block) < ChaCha20Poly1305AddLen+ChaCha20Poly1305SaltLen {
		return nil, ErrInvalidBufferStructure
	}
	buf := &ChaCha20Poly1305Buf{block: block}
	return buf, nil
}

func (buf *ChaCha20Poly1305Buf) Add() []byte {
	return buf.block[0:ChaCha20Poly1305AddLen]
}

func (buf *ChaCha20Poly1305Buf) Salt() []byte {
	const i = ChaCha20Poly1305AddLen
	const j = i + ChaCha20Poly1305SaltLen
	return buf.block[i:j]
}

func (buf *ChaCha20Poly1305Buf) Ciphertext() []byte {
	return buf.block[ChaCha20Poly1305AddLen+ChaCha20Poly1305SaltLen:]
}

func (buf *ChaCha20Poly1305Buf) Block() []byte {
	return buf.block
}

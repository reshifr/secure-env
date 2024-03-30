package crypt

type ChaCha20Poly1305Buf struct {
	buf []byte
}

func MakeChaCha20Poly1305Buf(add []byte, salt []byte,
	ciphertext []byte) (*ChaCha20Poly1305Buf, error) {
	if len(add) != ChaCha20Poly1305AddLen {
		return nil, ErrInvalidAddLen
	}
	if len(salt) != ChaCha20Poly1305SaltLen {
		return nil, ErrInvalidSaltLen
	}
	buf := []byte{}
	buf = append(buf, add...)
	buf = append(buf, salt...)
	buf = append(buf, ciphertext...)
	cpBuf := &ChaCha20Poly1305Buf{buf: buf}
	return cpBuf, nil
}

func LoadChaCha20Poly1305Buf(buf []byte) (*ChaCha20Poly1305Buf, error) {
	if len(buf) < ChaCha20Poly1305AddLen+ChaCha20Poly1305SaltLen {
		return nil, ErrInvalidBufferStructure
	}
	cpBuf := &ChaCha20Poly1305Buf{buf: buf}
	return cpBuf, nil
}

// func (aeadbuf *AEADBuf) Add() []byte {
// 	const i = AEADBufAddIndexPosition * AEADBufFieldLen
// 	const j = AEADBufAddLenPosition * AEADBufFieldLen
// 	const end = j + AEADBufFieldLen
// 	addIndex := binary.BigEndian.Uint64(aeadbuf.buf[i:j])
// 	addLen := binary.BigEndian.Uint64(aeadbuf.buf[j:end])
// 	return aeadbuf.buf[addIndex : addIndex+addLen]
// }

// func (aeadbuf *AEADBuf) Salt() []byte {
// 	const i = AEADBufSaltIndexPosition * AEADBufFieldLen
// 	const j = AEADBufSaltLenPosition * AEADBufFieldLen
// 	const end = j + AEADBufFieldLen
// 	saltIndex := binary.BigEndian.Uint64(aeadbuf.buf[i:j])
// 	saltLen := binary.BigEndian.Uint64(aeadbuf.buf[j:end])
// 	return aeadbuf.buf[saltIndex : saltLen+saltLen]
// }

// func (aeadbuf *AEADBuf) Ciphertext() []byte {
// 	const i = AEADBufCtIndexPosition * AEADBufFieldLen
// 	const j = AEADBufCtLenPosition * AEADBufFieldLen
// 	const end = j + AEADBufFieldLen
// 	ctIndex := binary.BigEndian.Uint64(aeadbuf.buf[i:j])
// 	ctLen := binary.BigEndian.Uint64(aeadbuf.buf[j:end])
// 	return aeadbuf.buf[ctIndex : ctIndex+ctLen]
// }

// func (aeadbuf *AEADBuf) Raw() []byte {
// 	return aeadbuf.buf
// }

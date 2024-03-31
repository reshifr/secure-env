package crypto_impl

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_MakeChaCha20Poly1305Buf(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidIVLen error", func(t *testing.T) {
		t.Parallel()
		// a := mock.NewCipherIV(t)
		// t.Log(a)
		// a := &IV96{}
		// b := mock.NewCipherIV(t)
		// t.Log(a)
		// t.Log(b)
		// crypt_mock.NewCipherIV(t)
		// iv := crypt_mock.NewCipherIV(t)
		// iv.EXPECT().Len().Return(8).Once()
		// add := [...]byte{
		// 	0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
		// 	0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
		// }
		// var expBuf *ChaCha20Poly1305Buf = nil

		// buf, err := MakeChaCha20Poly1305Buf(iv, add, ciphertext)
		// assert.Equal(t, expBuf, buf)
		// assert.Equal(t, err, nil)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		rawIV := bytes.Repeat([]byte{0xaa}, IV96Len)
		iv, _ := LoadIV96(rawIV)
		add := [...]byte{
			0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
			0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
		}
		ciphertext := bytes.Repeat([]byte{0xcc}, 7)
		block := []byte{}
		block = append(block, rawIV...)
		block = append(block, add[:]...)
		block = append(block, ciphertext...)
		expBuf := &ChaCha20Poly1305Buf{block: block}

		buf, err := MakeChaCha20Poly1305Buf(iv, add, ciphertext)
		assert.Equal(t, expBuf, buf)
		assert.Equal(t, err, nil)
	})
}

// func Test_LoadChaCha20Poly1305Buf(t *testing.T) {
// 	t.Parallel()
// 	t.Run("ErrInvalidBufferStructure error", func(t *testing.T) {
// 		t.Parallel()
// 		block := []byte{
// 			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
// 			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
// 		}
// 		var expBuf *ChaCha20Poly1305Buf = nil
// 		expErr := ErrInvalidBufferStructure

// 		buf, err := LoadChaCha20Poly1305Buf(block)
// 		assert.Equal(t, expBuf, buf)
// 		assert.ErrorIs(t, err, expErr)
// 	})
// 	t.Run("Succeed", func(t *testing.T) {
// 		t.Parallel()
// 		block := []byte{
// 			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
// 			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
// 			0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
// 		}
// 		expBuf := &ChaCha20Poly1305Buf{block: block}

// 		buf, err := LoadChaCha20Poly1305Buf(block)
// 		assert.Equal(t, expBuf, buf)
// 		assert.ErrorIs(t, err, nil)
// 	})
// }

// func Test_ChaCha20Poly1305Buf_Add(t *testing.T) {
// 	t.Parallel()
// 	buf := &ChaCha20Poly1305Buf{
// 		block: []byte{
// 			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
// 			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
// 			0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
// 		},
// 	}
// 	expAdd := bytes.Repeat([]byte{0xaa}, ChaCha20Poly1305AddLen)

// 	add := buf.Add()
// 	assert.Equal(t, expAdd, add)
// }

// func Test_ChaCha20Poly1305Buf_Ciphertext(t *testing.T) {
// 	t.Parallel()
// 	buf := &ChaCha20Poly1305Buf{
// 		block: []byte{
// 			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
// 			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
// 			0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
// 		},
// 	}
// 	expCiphertext := bytes.Repeat([]byte{0xbb}, 7)

// 	ciphertext := buf.Ciphertext()
// 	assert.Equal(t, expCiphertext, ciphertext)
// }

// func Test_ChaCha20Poly1305Buf_Block(t *testing.T) {
// 	t.Parallel()
// 	expBlock := []byte{
// 		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
// 		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
// 		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
// 	}
// 	buf := &ChaCha20Poly1305Buf{block: expBlock}

// 	block := buf.Block()
// 	assert.Equal(t, expBlock, block)
// }

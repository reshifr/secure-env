package crypto_impl

import (
	"bytes"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	"github.com/stretchr/testify/assert"
)

func Test_MakeIV96Buf(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidRawIVLen error", func(t *testing.T) {
		t.Parallel()
		rawIV := bytes.Repeat([]byte{0xaa}, 8)
		ciphertext := bytes.Repeat([]byte{0xbb}, 8)
		var expBuf *IV96Buf = nil
		expErr := crypto.ErrInvalidRawIVLen
		buf, err := MakeIV96Buf(rawIV, ciphertext)
		assert.Equal(t, expBuf, buf)
		assert.Equal(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		rawIV := bytes.Repeat([]byte{0xaa}, IV96Len)
		ciphertext := bytes.Repeat([]byte{0xbb}, 8)
		expBuf := &IV96Buf{rawIV: rawIV, ciphertext: ciphertext}
		buf, err := MakeIV96Buf(rawIV, ciphertext)
		assert.Equal(t, expBuf, buf)
		assert.Equal(t, err, nil)
	})
}

func Test_LoadIV96Buf(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidBuffer error", func(t *testing.T) {
		t.Parallel()
		rawBuf := bytes.Repeat([]byte{0xaa}, 8)
		var expBuf *IV96Buf = nil
		expErr := crypto.ErrInvalidBuffer
		buf, err := LoadIV96Buf(rawBuf)
		assert.Equal(t, expBuf, buf)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		rawIV := bytes.Repeat([]byte{0xaa}, IV96Len)
		ciphertext := bytes.Repeat([]byte{0xbb}, 8)
		rawBuf := []byte{
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
			0xbb, 0xbb, 0xbb, 0xbb,
		}
		expBuf := &IV96Buf{rawIV: rawIV, ciphertext: ciphertext}
		buf, err := LoadIV96Buf(rawBuf)
		assert.Equal(t, expBuf, buf)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_IV96Buf_RawIV(t *testing.T) {
	t.Parallel()
	rawBuf := []byte{
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
		0xbb, 0xbb, 0xbb, 0xbb,
	}
	buf, _ := LoadIV96Buf(rawBuf)
	expRawIV := bytes.Repeat([]byte{0xaa}, IV96Len)
	rawIV := buf.RawIV()
	assert.Equal(t, expRawIV, rawIV)
}

func Test_IV96Buf_Ciphertext(t *testing.T) {
	t.Parallel()
	rawBuf := []byte{
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
		0xbb, 0xbb, 0xbb, 0xbb,
	}
	buf, _ := LoadIV96Buf(rawBuf)
	expCiphertext := bytes.Repeat([]byte{0xbb}, 8)
	ciphertext := buf.Ciphertext()
	assert.Equal(t, expCiphertext, ciphertext)
}

func Test_IV96Buf_Raw(t *testing.T) {
	t.Parallel()
	rawIV := bytes.Repeat([]byte{0xaa}, IV96Len)
	ciphertext := bytes.Repeat([]byte{0xbb}, 8)
	expRaw := []byte{
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
		0xbb, 0xbb, 0xbb, 0xbb,
	}
	buf, _ := MakeIV96Buf(rawIV, ciphertext)
	raw := buf.Raw()
	assert.Equal(t, expRaw, raw)
}

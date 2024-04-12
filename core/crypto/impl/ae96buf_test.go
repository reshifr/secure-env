package crypto_impl

import (
	"bytes"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
	"github.com/stretchr/testify/assert"
)

func Test_MakeAE96Buf(t *testing.T) {
	t.Parallel()
	ciphertext := bytes.Repeat([]byte{0x22}, 8)

	t.Run("ErrInvalidIVLen error", func(t *testing.T) {
		t.Parallel()
		rawIV := bytes.Repeat([]byte{0x11}, 8)
		var expBuf *AE96Buf = nil
		expErr := crypto.ErrInvalidIVLen

		buf, err := MakeAE96Buf(rawIV, ciphertext)
		assert.Equal(t, expBuf, buf)
		assert.Equal(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		rawIV := bytes.Repeat([]byte{0x11}, AE96BufIVLen)
		expBuf := &AE96Buf{rawIV: rawIV, ciphertext: ciphertext}

		buf, err := MakeAE96Buf(rawIV, ciphertext)
		assert.Equal(t, expBuf, buf)
		assert.Equal(t, err, nil)
	})
}

func Test_LoadAE96Buf(t *testing.T) {
	t.Parallel()
	t.Run("ErrInvalidBufferLayout error", func(t *testing.T) {
		t.Parallel()
		rawBuf := bytes.Repeat([]byte{0x11}, 8)
		var expBuf *AE96Buf = nil
		expErr := crypto.ErrInvalidBufferLayout

		buf, err := LoadAE96Buf(rawBuf)
		assert.Equal(t, expBuf, buf)
		assert.ErrorIs(t, err, expErr)
	})
	t.Run("Succeed", func(t *testing.T) {
		t.Parallel()
		rawIV := bytes.Repeat([]byte{0x11}, AE96BufIVLen)
		ciphertext := bytes.Repeat([]byte{0x22}, 8)
		rawBuf := append(rawIV, ciphertext...)
		expBuf := &AE96Buf{rawIV: rawIV, ciphertext: ciphertext}

		buf, err := LoadAE96Buf(rawBuf)
		assert.Equal(t, expBuf, buf)
		assert.ErrorIs(t, err, nil)
	})
}

func Test_AE96Buf_Len(t *testing.T) {
	t.Parallel()
	rawIV := bytes.Repeat([]byte{0x11}, AE96BufIVLen)
	ciphertext := bytes.Repeat([]byte{0x22}, 8)
	expBufLen := AE96BufIVLen + len(ciphertext)

	buf, _ := MakeAE96Buf(rawIV, ciphertext)
	bufLen := buf.Len()
	assert.Equal(t, expBufLen, bufLen)
}

func Test_AE96Buf_RawIV(t *testing.T) {
	t.Parallel()
	expRawIV := bytes.Repeat([]byte{0x11}, AE96BufIVLen)
	ciphertext := bytes.Repeat([]byte{0x22}, 8)
	rawBuf := append(expRawIV, ciphertext...)

	buf, _ := LoadAE96Buf(rawBuf)
	rawIV := buf.RawIV()
	assert.Equal(t, expRawIV, rawIV)
}

func Test_AE96Buf_Ciphertext(t *testing.T) {
	t.Parallel()
	rawIV := bytes.Repeat([]byte{0x11}, AE96BufIVLen)
	expCiphertext := bytes.Repeat([]byte{0x22}, 8)
	rawBuf := append(rawIV, expCiphertext...)

	buf, _ := LoadAE96Buf(rawBuf)
	ciphertext := buf.Ciphertext()
	assert.Equal(t, expCiphertext, ciphertext)
}

func Test_AE96Buf_Raw(t *testing.T) {
	t.Parallel()
	rawIV := bytes.Repeat([]byte{0x11}, AE96BufIVLen)
	ciphertext := bytes.Repeat([]byte{0x22}, 8)
	expRawBuf := append(rawIV, ciphertext...)

	buf, _ := LoadAE96Buf(expRawBuf)
	rawBuf := buf.Raw()
	assert.Equal(t, expRawBuf, rawBuf)
}

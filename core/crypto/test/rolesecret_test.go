package crypto_test

import (
	"crypto/md5"
	"crypto/rand"
	"testing"

	c "github.com/reshifr/secure-env/core/crypto"
	cimpl "github.com/reshifr/secure-env/core/crypto/impl"
	cmock "github.com/reshifr/secure-env/core/crypto/mock"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/hkdf"
)

func Test_RoleSecret_Raw(t *testing.T) {
	t.Parallel()
	kdf := cmock.NewKDF(t)
	kdf.EXPECT().Key(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
		func(passphrase string, salt []byte, keyLen uint32) []byte {
			hval := make([]byte, keyLen)
			h := hkdf.New(md5.New, []byte(passphrase), salt, nil)
			h.Read(hval)
			return hval
		}).Maybe()

	fn := c.FnCSPRNG{Read: rand.Read}
	rng := cimpl.NewAutoRNG(fn)
	cipher := cimpl.ChaChaPolyAE{}
	secret, err := cimpl.MakeRoleSecret(kdf, rng, cipher)
	if err != nil {
		t.Fatal(err)
	}

	rawIV := [cimpl.GlobalIV96Len]byte{}
	if err := rng.Read(rawIV[:]); err != nil {
		t.Fatal(err)
	}
	iv, err := cimpl.LoadGlobalIV96(rawIV[:])
	if err != nil {
		t.Fatal(err)
	}
	passphrases := []string{
		"cKN8y~yQ@GkY1&D_",
		"I,Jv0Aic/RG.RF_K",
		"4+/mqVQy5wmknWp4",
		"Fy_Z7NUB_r+8_nq5",
		"n06vobd3FMJbf+rI",
		"Za6i88X-9VW?UppK",
		"qm4_NhqU?@CjuvZr",
	}
	for _, passphrase := range passphrases {
		id, err := secret.Add(iv, passphrase)
		if err != nil {
			t.Fatal(err, id)
		}
	}

	secret.Del(100)
	secret.Del(5)
	secret.Del(2)
	raw := secret.Raw()
	// t.Logf("Raw: %x\n", raw)

	secret2, err := cimpl.LoadRoleSecret(kdf, rng, cipher, raw, 3, passphrases[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Log(secret2)
	t.Logf("Raw2 %x\n", secret2.Raw())

	// bitmap := binary.BigEndian.Uint64(raw)
	// t.Logf("Bitmap: %064b\n", bitmap)
	// t.Logf("Bitmap: %016x\n", bitmap)
	// i := cimpl.RoleSecretBitmapSize
	// bufLen := int(raw[i])
	// t.Logf("BufLen: %v\n", bufLen)
	// i += cimpl.RoleSecretBufLenSize
	// order := 0
	// for len(raw[i:]) != 0 {
	// 	t.Logf("Salt[%v]: %x\n", order, raw[i:i+cimpl.RoleSecretSaltLen])
	// 	i += cimpl.RoleSecretSaltLen
	// 	t.Logf("Buf[%v]: %x\n", order, raw[i:i+cimpl.AE96BufIVLen])
	// 	t.Logf("Buf[%v]: %x\n", order, raw[i+cimpl.AE96BufIVLen:i+bufLen])
	// 	i += bufLen
	// 	order++
	// }

	// t.Log(len(raw))
	// t.Log(i)
}

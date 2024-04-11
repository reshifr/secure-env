package crypto_test

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"testing"

	c "github.com/reshifr/secure-env/core/crypto"
	cimpl "github.com/reshifr/secure-env/core/crypto/impl"
	cmock "github.com/reshifr/secure-env/core/crypto/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/hkdf"
)

func Test_RoleSecret_Make_Encrypt_Decrypt(t *testing.T) {
	t.Parallel()
	kdf := cmock.NewKDF(t)
	kdf.EXPECT().Key(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
		func(passphrase string, salt []byte, keyLen uint32) []byte {
			hval := make([]byte, keyLen)
			h := hkdf.New(md5.New, []byte(passphrase), salt, nil)
			h.Read(hval)
			return hval
		}).Maybe()

	fnRNG := c.FnCSPRNG{Read: rand.Read}
	rng := cimpl.NewAutoRNG(fnRNG)
	cipher := cimpl.ChaCha20Poly1305AE{}

	ownerIVFixed := [cimpl.IV96FixedLen]byte{}
	if err := rng.Read(ownerIVFixed[:]); err != nil {
		t.Fatal(err)
	}
	ownerIV, err := cimpl.MakeIV96(ownerIVFixed[:])
	if err != nil {
		t.Fatal(err)
	}
	passphrase := "RodGY-gV7vpz6FHZ6zEKQEhl1.kKz1S,"
	secret, _, err := cimpl.MakeRoleSecret(kdf, rng, cipher, ownerIV, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	passphrases := []string{
		",zNdmrWKH1NKp.9JT5HzaW=zlD,?PMI#",
		"lymHS7/.Zwcv-nBWjs6V3O~r@1T~fRCN",
		",bEZhF~g.~rvYJmy+BEJEkGrw@8DKx@S",
		"yqt_nw8g+8ktYWQ&j.clx/=YuUd~/Fpf",
		"+ePmPAfuEGZ.JCUTvLh3m3j@=fvqFUyO",
		"RjC=Ra?CG7qExj&/BL/refbo7QJqR_tr",
	}
	for _, passphrase := range passphrases {
		memberIVFixed := [cimpl.IV96FixedLen]byte{}
		if err := rng.Read(memberIVFixed[:]); err != nil {
			t.Fatal(err)
		}
		memberIV, err := cimpl.MakeIV96(memberIVFixed[:])
		if err != nil {
			t.Fatal(err)
		}
		secret.Add(memberIV, passphrase)
	}

	msg := []byte("Hello, World!")
	buf := secret.Encrypt(msg)
	plaintext, err := secret.Decrypt(buf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, msg, plaintext)

	raw := secret.Raw()
	i := 0
	bitmap := binary.BigEndian.Uint64(raw[i:])
	t.Logf("Bitmap: %064b\n", bitmap)
	i += cimpl.RoleSecretBitmapSize
	bufLen := int(binary.BigEndian.Uint64(raw[i:]))
	t.Logf("BufLen: %v\n", bufLen)
	i += cimpl.RoleSecretBufLenSize
	t.Logf("IV: %x\n", raw[i:i+cimpl.IV96Len])
	i += cimpl.IV96Len
	order := 0
	for len(raw[i:]) != 0 {
		t.Logf("Salt[%v]: %x\n", order, raw[i:i+cimpl.RoleSecretSaltLen])
		i += cimpl.RoleSecretSaltLen
		t.Logf("Buf[%v]: %x\n", order, raw[i:i+bufLen])
		i += bufLen
		order++
	}

	t.Log(len(raw))
	t.Log(i)
}

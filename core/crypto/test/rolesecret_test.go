package crypto_test

import (
	"crypto/md5"
	"crypto/rand"
	"testing"

	c "github.com/reshifr/secure-env/core/crypto"
	cimpl "github.com/reshifr/secure-env/core/crypto/impl"
	cmock "github.com/reshifr/secure-env/core/crypto/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/hkdf"
)

func Test_RoleSecret_Make_Seal_Open(t *testing.T) {
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
	cipher := cimpl.NewChaCha20Poly1305(rng)

	fixed := [cimpl.IV96FixedLen]byte{}
	if err := rng.Read(fixed[:]); err != nil {
		t.Fatal(err)
	}
	roleIV, err := cimpl.MakeIV96(fixed[:])
	if err != nil {
		t.Fatal(err)
	}
	sec, err := cimpl.MakeRoleSecret(kdf, rng, cipher, roleIV)
	if err != nil {
		t.Fatal(err)
	}

	passphrases := [...]string{
		"RodGY-gV7vpz6FHZ6zEKQEhl1.kKz1S,",
		",zNdmrWKH1NKp.9JT5HzaW=zlD,?PMI#",
		"lymHS7/.Zwcv-nBWjs6V3O~r@1T~fRCN",
		",bEZhF~g.~rvYJmy+BEJEkGrw@8DKx@S",
		"yqt_nw8g+8ktYWQ&j.clx/=YuUd~/Fpf",
		"+ePmPAfuEGZ.JCUTvLh3m3j@=fvqFUyO",
		"RjC=Ra?CG7qExj&/BL/refbo7QJqR_tr",
	}
	for _, passphrase := range passphrases {
		fixed := [cimpl.IV96FixedLen]byte{}
		if err := rng.Read(fixed[:]); err != nil {
			t.Fatal(err)
		}
		userIV, err := cimpl.MakeIV96(fixed[:])
		if err != nil {
			t.Fatal(err)
		}
		sec.Add(userIV, passphrase)
	}

	msg := []byte("Hello, World!")
	buf, err := sec.Seal(msg)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := sec.Open(buf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, msg, plaintext)
}

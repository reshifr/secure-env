package crypto_impl

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/reshifr/secure-env/core/crypto"
)

func Test_Main(t *testing.T) {
	t.Skip()
	kdf := Argon2{}
	fnRNG := crypto.FnCSPRNG{Read: rand.Read}
	rng := NewAutoRNG(fnRNG)
	cipher := NewChaCha20Poly1305(rng)

	roleIV, _ := MakeIV96(bytes.Repeat([]byte{0x11}, IV96FixedLen))
	mak, _ := NewMultiAccessKey(kdf, rng, cipher, roleIV)

	userIV, _ := MakeIV96(bytes.Repeat([]byte{0x22}, IV96FixedLen))
	for i := 0; i < 100; i++ {
		id, _ := mak.Add(userIV, "Renol")
		t.Logf("ID: %v\n", id)
	}

	t.Logf("Bitmap: %b\n", mak.bitmap)
	t.Logf("ObjIV: %x\n", mak.iv.Raw())
	t.Logf("SharedKey: %x\n", mak.sharedKey)
	for id, val := range mak.encryptedKeys {
		t.Logf("EncrKeys[%v][Salt]: %x\n", id, val.salt)
		t.Logf("EncrKeys[%v][Chiperbuf]: %x\n", id, val.buf.Block())
	}
	t.Logf("EncrKeysLen: %v\n", len(mak.encryptedKeys))
}

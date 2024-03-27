package main

import (
	"fmt"

	"github.com/reshifr/secure-env/core/crypt"
	"github.com/reshifr/secure-env/core/std"
)

func main() {
	var h std.Argon2
	kdf := crypt.NewKDF(h)
	fmt.Println(kdf.PassphraseKey("Hello, CLI!", []byte{}, 16))
}

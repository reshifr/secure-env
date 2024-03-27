package main

import (
	"fmt"

	"github.com/reshifr/secure-env/core"
	"github.com/reshifr/secure-env/core/crypt"
)

func main() {
	var h core.Argon2
	kdf := crypt.NewKDF(h)
	fmt.Println(kdf.PassphraseKey("Hello, CLI!", []byte{}, 16))
}

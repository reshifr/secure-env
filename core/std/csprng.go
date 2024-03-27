package std

import (
	"crypto/rand"
)

type CSPRNG struct{}

func (rng CSPRNG) Read(block []byte) error {
	_, err := rand.Read(block)
	return err
}

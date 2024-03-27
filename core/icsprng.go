package core

type ICSPRNG interface {
	Read(block []byte) (err error)
}

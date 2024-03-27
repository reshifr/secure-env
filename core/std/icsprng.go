package std

type ICSPRNG interface {
	Read(block []byte) (err error)
}

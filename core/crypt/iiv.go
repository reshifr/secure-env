package crypt

type IVError int

const (
	ErrInvalidRawIVLen IVError = iota + 1
)

func (IVError) Error() string {
	return "ErrInvalidRawIVLen: invalid raw IV size."
}

type IIV interface {
	Invoke()
	Raw() (rawIV []byte)
	Len() (ivLen int)
}

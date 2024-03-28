package crypt

type IVError int

const (
	ErrIVInvalidLen IVError = iota + 1
)

func (err IVError) Error() string {
	return "ErrIVInvalidLen: invalid size of raw IV."
}

type IIV interface {
	Invoke()
	Raw() (rawIV []byte)
	Len() (ivLen int)
}

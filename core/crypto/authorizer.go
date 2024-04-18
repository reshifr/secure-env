package crypto

type AuthorizerError int

const (
	ErrInvalidBlockLen AuthorizerError = iota + 1
)

func (err AuthorizerError) Error() string {
	switch err {
	case ErrInvalidBlockLen:
		return "ErrInvalidBlockLen: ... ."
	default:
		return "Error: unknown."
	}
}

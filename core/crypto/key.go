package crypto

type KeyError int

const (
	ErrKeyExceedsLimit KeyError = iota + 1
)

func (KeyError) Error() string {
	return "ErrKeyExceedsLimit: maximum keys allowed is 64."
}

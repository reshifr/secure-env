package crypto

type SecretError int

const (
	ErrSharingExceedsLimit SecretError = iota + 1
)

func (SecretError) Error() string {
	return "ErrSharingExceedsLimit: maximum shared secret is 64."
}

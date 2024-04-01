package crypto

type SecretError int

const (
	ErrSecretSharingExceedsLimit SecretError = iota + 1
)

func (SecretError) Error() string {
	return "ErrSecretSharingExceedsLimit: maximum shared secret is 64."
}

package crypto

type SecretError int

const (
	ErrSharingExceedsLimit SecretError = iota + 1
	ErrInvalidSecretId
	ErrIdDoesNotExist
)

func (err SecretError) Error() string {
	switch err {
	case ErrSharingExceedsLimit:
		return "ErrSharingExceedsLimit: " +
			"the number of shared keys has exceeded the limit."
	case ErrInvalidSecretId:
		return "ErrInvalidSecretId: invalid secret id"
	case ErrIdDoesNotExist:
		return "ErrIdDoesNotExist: the secret id doesn't exist in the shared keys"
	default:
		return "Error: unknown."
	}
}

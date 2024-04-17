package crypto

type RoleSecretError int

const (
	ErrSharingExceedsLimit RoleSecretError = iota + 1
	ErrInvalidSecretId
	ErrBrokenSecretIntegrity
	ErrIdDoesNotExist
)

func (err RoleSecretError) Error() string {
	switch err {
	case ErrSharingExceedsLimit:
		return "ErrSharingExceedsLimit: " +
			"the number of shared keys has exceeded the limit."
	case ErrInvalidSecretId:
		return "ErrInvalidSecretId: invalid secret id"
	case ErrBrokenSecretIntegrity:
		return "ErrBrokenSecretIntegrity: the secret integrity has been broken"
	case ErrIdDoesNotExist:
		return "ErrIdDoesNotExist: the secret id doesn't exist in the shared keys"
	default:
		return "Error: unknown."
	}
}

type RoleSecret interface{}

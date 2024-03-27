package std

type IArgon2 interface {
	Key(
		password []byte,
		salt []byte,
		time uint32,
		memory uint32,
		threads uint8,
		keyLen uint32) (key []byte)
}

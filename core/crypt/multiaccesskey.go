package crypt

const (
	MultiAccessKeySaltLen = 16
)

type MultiAccessKey[KDF IKDF, CSPRNG ICSPRNG, Cipher ICipher] struct {
	kdf           KDF
	csprng        CSPRNG
	cipher        Cipher
	bitmap        uint64
	iv            ICipherIV
	sharedKey     []byte
	encryptedKeys map[int8]ICipherBuf
}

func NewMultiAccessKey[KDF IKDF, CSPRNG ICSPRNG, Cipher ICipher](
	kdf KDF, csprng CSPRNG, cipher Cipher, iv ICipherIV) (
	*MultiAccessKey[KDF, CSPRNG, Cipher], error) {
	sharedKey, err := csprng.Make(int(cipher.KeyLen()))
	if err != nil {
		return nil, ErrReadEntropyFailed
	}
	mak := &MultiAccessKey[KDF, CSPRNG, Cipher]{
		kdf:       kdf,
		csprng:    csprng,
		cipher:    cipher,
		iv:        iv,
		sharedKey: sharedKey,
	}
	return mak, nil
}

func (mak *MultiAccessKey[KDF, CSPRNG, Cipher]) id() int8 {
	i := int8(0)
	n := ^mak.bitmap
	if n >= uint64(0x0000000100000000) {
		i += 32
		n >>= 32
	}
	if n >= uint64(0x0000000000010000) {
		i += 16
		n >>= 16
	}
	if n >= uint64(0x0000000000000100) {
		i += 8
		n >>= 8
	}
	if n >= uint64(0x0000000000000010) {
		i += 4
		n >>= 4
	}
	if n >= uint64(0x0000000000000004) {
		i += 2
		n >>= 2
	}
	if n >= uint64(0x0000000000000002) {
		i += 1
		n >>= 1
	}
	mak.bitmap |= uint64(1) << i
	return i
}

func (mak *MultiAccessKey[KDF, CSPRNG, Cipher]) Add(
	iv ICipherIV, passphrase string) (int8, error) {
	if ^mak.bitmap == 0 {
		return -1, ErrKeyExceedsLimit
	}
	salt := [MultiAccessKeySaltLen]byte{}
	if err := mak.csprng.Read(salt[:]); err != nil {
		return -1, err
	}
	privateKey := mak.kdf.Key(passphrase, salt[:], mak.cipher.KeyLen())
	encryptedKey, err := mak.cipher.Seal(iv, privateKey, mak.sharedKey)
	if err != nil {
		return -1, err
	}
	id := mak.id()
	mak.encryptedKeys[id] = encryptedKey
	return id, nil
}

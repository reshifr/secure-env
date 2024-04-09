package bits

func POPCNT64(n uint64) int {
	n -= (n >> 1) & 0x5555555555555555
	n = (n & 0x3333333333333333) + ((n >> 2) & 0x3333333333333333)
	n = (n + (n >> 4)) & 0x0f0f0f0f0f0f0f0f
	return int((n * 0x0101010101010101) >> 56)
}

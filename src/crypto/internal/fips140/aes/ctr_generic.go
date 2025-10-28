//go:build !purego

package aes

func ctrXORKeyStreamAtGeneric(c *CTR, dst, src []byte, offset uint64) {
	ivlo, ivhi := add128(c.ivlo, c.ivhi, offset/BlockSize)

	if blockOffset := offset % BlockSize; blockOffset != 0 {
		// We have a partial block at the beginning.
		var in, out [BlockSize]byte
		copy(in[blockOffset:], src)
		ctrBlocks1(&c.b, &out, &in, ivlo, ivhi)
		n := copy(dst, out[blockOffset:])
		src = src[n:]
		dst = dst[n:]
		ivlo, ivhi = add128(ivlo, ivhi, 1)
	}

	for len(src) >= 8*BlockSize {
		ctrBlocks8(&c.b, (*[8 * BlockSize]byte)(dst), (*[8 * BlockSize]byte)(src), ivlo, ivhi)
		src = src[8*BlockSize:]
		dst = dst[8*BlockSize:]
		ivlo, ivhi = add128(ivlo, ivhi, 8)
	}

	// The tail can have at most 7 = 4 + 2 + 1 blocks.
	if len(src) >= 4*BlockSize {
		ctrBlocks4(&c.b, (*[4 * BlockSize]byte)(dst), (*[4 * BlockSize]byte)(src), ivlo, ivhi)
		src = src[4*BlockSize:]
		dst = dst[4*BlockSize:]
		ivlo, ivhi = add128(ivlo, ivhi, 4)
	}
	if len(src) >= 2*BlockSize {
		ctrBlocks2(&c.b, (*[2 * BlockSize]byte)(dst), (*[2 * BlockSize]byte)(src), ivlo, ivhi)
		src = src[2*BlockSize:]
		dst = dst[2*BlockSize:]
		ivlo, ivhi = add128(ivlo, ivhi, 2)
	}
	if len(src) >= 1*BlockSize {
		ctrBlocks1(&c.b, (*[1 * BlockSize]byte)(dst), (*[1 * BlockSize]byte)(src), ivlo, ivhi)
		src = src[1*BlockSize:]
		dst = dst[1*BlockSize:]
		ivlo, ivhi = add128(ivlo, ivhi, 1)
	}

	if len(src) != 0 {
		// We have a partial block at the end.
		var in, out [BlockSize]byte
		copy(in[:], src)
		ctrBlocks1(&c.b, &out, &in, ivlo, ivhi)
		copy(dst, out[:])
	}
}

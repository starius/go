//go:build arm64 && !purego

// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes

//go:generate sh -c "go run ./ctr_arm64_gen.go | asmfmt > ctr_arm64.s"

//go:noescape
func ctrAsm(nr int, xk *[60]uint32, dst, src *byte, headSkip, headLen, blocks, tailLen int, ivlo, ivhi uint64)

func ctrBlocks1(b *Block, dst, src *[BlockSize]byte, ivlo, ivhi uint64) {
	if !supportsAES {
		ctrBlocks(b, dst[:], src[:], ivlo, ivhi)
		return
	}
	ctrAsm(b.rounds, &b.enc, &dst[0], &src[0], 0, 0, 1, 0, ivlo, ivhi)
}

func ctrBlocks2(b *Block, dst, src *[2 * BlockSize]byte, ivlo, ivhi uint64) {
	if !supportsAES {
		ctrBlocks(b, dst[:], src[:], ivlo, ivhi)
		return
	}
	ctrAsm(b.rounds, &b.enc, &dst[0], &src[0], 0, 0, 2, 0, ivlo, ivhi)
}

func ctrBlocks4(b *Block, dst, src *[4 * BlockSize]byte, ivlo, ivhi uint64) {
	if !supportsAES {
		ctrBlocks(b, dst[:], src[:], ivlo, ivhi)
		return
	}
	ctrAsm(b.rounds, &b.enc, &dst[0], &src[0], 0, 0, 4, 0, ivlo, ivhi)
}

func ctrBlocks8(b *Block, dst, src *[8 * BlockSize]byte, ivlo, ivhi uint64) {
	if !supportsAES {
		ctrBlocks(b, dst[:], src[:], ivlo, ivhi)
		return
	}
	ctrAsm(b.rounds, &b.enc, &dst[0], &src[0], 0, 0, 8, 0, ivlo, ivhi)
}

func ctrXORKeyStreamAt(c *CTR, dst, src []byte, offset uint64) {
	if !supportsAES {
		ctrXORKeyStreamAtGeneric(c, dst, src, offset)
		return
	}

	if len(src) == 0 {
		return
	}

	ivlo, ivhi := add128(c.ivlo, c.ivhi, offset/BlockSize)

	headSkip := int(offset % BlockSize)
	headLen := 0
	if headSkip != 0 {
		headLen = BlockSize - headSkip
		if headLen > len(src) {
			headLen = len(src)
		}
	}

	remaining := len(src) - headLen
	fullBlocks := remaining / BlockSize
	tailLen := remaining - fullBlocks*BlockSize

	ctrAsm(c.b.rounds, &c.b.enc, &dst[0], &src[0], headSkip, headLen, fullBlocks, tailLen, ivlo, ivhi)
}

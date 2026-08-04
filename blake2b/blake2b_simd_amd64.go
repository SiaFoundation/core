//go:build goexperiment.simd

package blake2b

import (
	"simd/archsimd"
	"unsafe"
)

// All of our messages have the same length and consist of a single block. This
// means we can precompute the initial state for each hash.
var initState = [16]uint64{
	// h0 .. h7: iv ^ parameter block (digest length 32, fanout 1, depth 1)
	0x6a09e667f2bdc928,
	0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b,
	0xa54ff53a5f1d36f1,
	0x510e527fade682d1,
	0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b,
	0x5be0cd19137e2179,
	// v8 .. v15: the raw iv, with the counter and final-block flag xor'd in
	0x6a09e667f3bcc908,
	0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b,
	0xa54ff53a5f1d36f1,
	0x510e527fade68290, // xor'd with 65 (input length)
	0x9b05688c2b3e6c1f,
	0xe07c265404be4294, // xor'd with ~0 (final block)
	0x5be0cd19137e2179,
}

// initVectors is initState with each word broadcast to all four lanes, so that
// the round setup is a plain load. The finalize step deliberately broadcasts
// from initState instead; sharing the expression would let CSE pin those four
// vectors across all twelve rounds, forcing the state to spill.
var initVectors = func() (vs [16][4]uint64) {
	for i, x := range initState {
		vs[i] = [4]uint64{x, x, x, x}
	}
	return
}()

// Right-shift counts, held as vectors so that the shifts use the variable-count
// form (VPSRLVQ) rather than the broadcast-count one (VPSRLQ): vec63 for g's
// 63-bit rotation, vec56 for hashBlocksAVX2's prefix shift. ShiftAllRight with
// a constant count would be simpler, but the compiler has no immediate-folding
// rule for VPSRL*, so it lowers to two uops, one of them on the shuffle port
// that the rounds already bottleneck on.
var (
	vec63 = [4]uint64{63, 63, 63, 63}
	vec56 = [4]uint64{56, 56, 56, 56}
)

// Shuffle tables for g's byte-granular rotations. A rotation by a whole number
// of bytes is a single VPSHUFB.
var (
	shuffleRot16 = genRot(2)
	shuffleRot24 = genRot(3)
)

// genRot returns the VPSHUFB table that rotates each uint64 right by n bytes.
func genRot(n int) (idx [32]int8) {
	// in VPSHUFB, each byte selects a source byte within its 128-bit group:
	// (i & 8) picks the 8-byte word, (i+n)%8 the byte within it
	for i := range idx {
		idx[i] = int8((i & 8) + (i+n)%8)
	}
	return
}

// transpose4 transposes a 4x4 matrix of uint64s held in four vectors.
func transpose4(x0, x1, x2, x3 archsimd.Uint64x4) (_, _, _, _ archsimd.Uint64x4) {
	// interleave each uint64, then interleave the 128-bit halves
	t0 := x0.InterleaveLoGrouped(x1)
	t1 := x0.InterleaveHiGrouped(x1)
	t2 := x2.InterleaveLoGrouped(x3)
	t3 := x2.InterleaveHiGrouped(x3)
	return t0.Select128FromPair(0, 2, t2),
		t1.Select128FromPair(0, 2, t3),
		t0.Select128FromPair(1, 3, t2),
		t1.Select128FromPair(1, 3, t3)
}

// loadWords loads words i through i+3 of msg.
func loadWords(msg *[64]byte, i int) archsimd.Uint64x4 {
	return archsimd.LoadUint64x4((*[4]uint64)(unsafe.Pointer(&msg[i*8])))
}

// g is the BLAKE2b mixing function. hashBlocksAVX2 applies it to four blocks at
// once, one state word per vector; hashBlockAVX2 applies it to the four columns
// of a single block, one state row per vector.
//
// Each mix adds two message words to a; callers add the first themselves, which
// keeps it off the dependency chain. A nil my means that word is zero, and since
// every call site passes a constant, the branch folds at compile time.
func g(a, b, c, d archsimd.Uint64x4, my *[4]uint64) (_, _, _, _ archsimd.Uint64x4) {
	a = a.Add(b)
	// rotating by 32 bits is a swap of each uint64's halves, so an immediate
	// dword shuffle does it without a third shuffle table
	d = d.Xor(a).AsUint32x8().PermuteScalarsGrouped(1, 0, 3, 2).AsUint64x4()
	c = c.Add(d)
	b = b.Xor(c).AsUint8x32().PermuteOrZeroGrouped(archsimd.LoadInt8x32(&shuffleRot24)).AsUint64x4()
	if my != nil {
		a = a.Add(archsimd.LoadUint64x4(my)).Add(b)
	} else {
		a = a.Add(b)
	}
	d = d.Xor(a).AsUint8x32().PermuteOrZeroGrouped(archsimd.LoadInt8x32(&shuffleRot16)).AsUint64x4()
	c = c.Add(d)
	b = b.Xor(c)
	// rotate right by 63, i.e. left by 1; Add doubles rather than
	// ShiftAllLeft(1) so that it can issue on any vector port
	b = b.ShiftRight(archsimd.LoadUint64x4(&vec63)).Or(b.Add(b))
	return a, b, c, d
}

func hashBlocksAVX2(outs *[4][32]byte, msgs *[4][64]byte, prefix uint64) {
	// transpose the four messages into nine vectors. The logical messages are a
	// prefix byte followed by 64 message bytes; the prefix is shifted in after
	// transposing so that no load crosses a message boundary. AVX2 has no 64-bit
	// funnel shift (VPSHLDQ is AVX512, VPALIGNR works on 128-bit lanes), so each
	// word takes a shift, a shift and an or. Kept inline because the compiler
	// won't inline a helper this size.
	var block [9][4]uint64
	rsh := archsimd.LoadUint64x4(&vec56)
	w0, w1, w2, w3 := transpose4(loadWords(&msgs[0], 0), loadWords(&msgs[1], 0), loadWords(&msgs[2], 0), loadWords(&msgs[3], 0))
	w4, w5, w6, w7 := transpose4(loadWords(&msgs[0], 4), loadWords(&msgs[1], 4), loadWords(&msgs[2], 4), loadWords(&msgs[3], 4))
	w0.ShiftAllLeft(8).Or(archsimd.BroadcastUint64x4(prefix)).Store(&block[0])
	w1.ShiftAllLeft(8).Or(w0.ShiftRight(rsh)).Store(&block[1])
	w2.ShiftAllLeft(8).Or(w1.ShiftRight(rsh)).Store(&block[2])
	w3.ShiftAllLeft(8).Or(w2.ShiftRight(rsh)).Store(&block[3])
	w4.ShiftAllLeft(8).Or(w3.ShiftRight(rsh)).Store(&block[4])
	w5.ShiftAllLeft(8).Or(w4.ShiftRight(rsh)).Store(&block[5])
	w6.ShiftAllLeft(8).Or(w5.ShiftRight(rsh)).Store(&block[6])
	w7.ShiftAllLeft(8).Or(w6.ShiftRight(rsh)).Store(&block[7])
	w7.ShiftRight(rsh).Store(&block[8])

	// round setup; each of the 16 state vectors holds one state word for all
	// four hashes
	v0 := archsimd.LoadUint64x4(&initVectors[0])
	v1 := archsimd.LoadUint64x4(&initVectors[1])
	v2 := archsimd.LoadUint64x4(&initVectors[2])
	v3 := archsimd.LoadUint64x4(&initVectors[3])
	v4 := archsimd.LoadUint64x4(&initVectors[4])
	v5 := archsimd.LoadUint64x4(&initVectors[5])
	v6 := archsimd.LoadUint64x4(&initVectors[6])
	v7 := archsimd.LoadUint64x4(&initVectors[7])
	v8 := archsimd.LoadUint64x4(&initVectors[8])
	v9 := archsimd.LoadUint64x4(&initVectors[9])
	v10 := archsimd.LoadUint64x4(&initVectors[10])
	v11 := archsimd.LoadUint64x4(&initVectors[11])
	v12 := archsimd.LoadUint64x4(&initVectors[12])
	v13 := archsimd.LoadUint64x4(&initVectors[13])
	v14 := archsimd.LoadUint64x4(&initVectors[14])
	v15 := archsimd.LoadUint64x4(&initVectors[15])

	// the rounds are fully unrolled: spelling out each round's permutation is
	// what lets g's zero-message branches fold, and a loop over a permutation
	// table would pin the state to one register assignment across the back edge.
	// Within a half-round the four mixes are independent, so they are emitted
	// last-to-first, which spills less.
	//
	// round 1
	v3, v7, v11, v15 = g(v3.Add(archsimd.LoadUint64x4(&block[6])), v7, v11, v15, &block[7])
	v2, v6, v10, v14 = g(v2.Add(archsimd.LoadUint64x4(&block[4])), v6, v10, v14, &block[5])
	v1, v5, v9, v13 = g(v1.Add(archsimd.LoadUint64x4(&block[2])), v5, v9, v13, &block[3])
	v0, v4, v8, v12 = g(v0.Add(archsimd.LoadUint64x4(&block[0])), v4, v8, v12, &block[1])
	v3, v4, v9, v14 = g(v3, v4, v9, v14, nil)
	v2, v7, v8, v13 = g(v2, v7, v8, v13, nil)
	v1, v6, v11, v12 = g(v1, v6, v11, v12, nil)
	v0, v5, v10, v15 = g(v0.Add(archsimd.LoadUint64x4(&block[8])), v5, v10, v15, nil)
	// round 2
	v3, v7, v11, v15 = g(v3, v7, v11, v15, &block[6])
	v2, v6, v10, v14 = g(v2, v6, v10, v14, nil)
	v1, v5, v9, v13 = g(v1.Add(archsimd.LoadUint64x4(&block[4])), v5, v9, v13, &block[8])
	v0, v4, v8, v12 = g(v0, v4, v8, v12, nil)
	v3, v4, v9, v14 = g(v3.Add(archsimd.LoadUint64x4(&block[5])), v4, v9, v14, &block[3])
	v2, v7, v8, v13 = g(v2, v7, v8, v13, &block[7])
	v1, v6, v11, v12 = g(v1.Add(archsimd.LoadUint64x4(&block[0])), v6, v11, v12, &block[2])
	v0, v5, v10, v15 = g(v0.Add(archsimd.LoadUint64x4(&block[1])), v5, v10, v15, nil)
	// round 3
	v3, v7, v11, v15 = g(v3, v7, v11, v15, nil)
	v2, v6, v10, v14 = g(v2.Add(archsimd.LoadUint64x4(&block[5])), v6, v10, v14, &block[2])
	v1, v5, v9, v13 = g(v1, v5, v9, v13, &block[0])
	v0, v4, v8, v12 = g(v0, v4, v8, v12, &block[8])
	v3, v4, v9, v14 = g(v3, v4, v9, v14, &block[4])
	v2, v7, v8, v13 = g(v2.Add(archsimd.LoadUint64x4(&block[7])), v7, v8, v13, &block[1])
	v1, v6, v11, v12 = g(v1.Add(archsimd.LoadUint64x4(&block[3])), v6, v11, v12, &block[6])
	v0, v5, v10, v15 = g(v0, v5, v10, v15, nil)
	// round 4
	v3, v7, v11, v15 = g(v3, v7, v11, v15, nil)
	v2, v6, v10, v14 = g(v2, v6, v10, v14, nil)
	v1, v5, v9, v13 = g(v1.Add(archsimd.LoadUint64x4(&block[3])), v5, v9, v13, &block[1])
	v0, v4, v8, v12 = g(v0.Add(archsimd.LoadUint64x4(&block[7])), v4, v8, v12, nil)
	v3, v4, v9, v14 = g(v3, v4, v9, v14, &block[8])
	v2, v7, v8, v13 = g(v2.Add(archsimd.LoadUint64x4(&block[4])), v7, v8, v13, &block[0])
	v1, v6, v11, v12 = g(v1.Add(archsimd.LoadUint64x4(&block[5])), v6, v11, v12, nil)
	v0, v5, v10, v15 = g(v0.Add(archsimd.LoadUint64x4(&block[2])), v5, v10, v15, &block[6])
	// round 5
	v3, v7, v11, v15 = g(v3, v7, v11, v15, nil)
	v2, v6, v10, v14 = g(v2.Add(archsimd.LoadUint64x4(&block[2])), v6, v10, v14, &block[4])
	v1, v5, v9, v13 = g(v1.Add(archsimd.LoadUint64x4(&block[5])), v5, v9, v13, &block[7])
	v0, v4, v8, v12 = g(v0, v4, v8, v12, &block[0])
	v3, v4, v9, v14 = g(v3.Add(archsimd.LoadUint64x4(&block[3])), v4, v9, v14, nil)
	v2, v7, v8, v13 = g(v2.Add(archsimd.LoadUint64x4(&block[6])), v7, v8, v13, &block[8])
	v1, v6, v11, v12 = g(v1, v6, v11, v12, nil)
	v0, v5, v10, v15 = g(v0, v5, v10, v15, &block[1])
	// round 6
	v3, v7, v11, v15 = g(v3.Add(archsimd.LoadUint64x4(&block[8])), v7, v11, v15, &block[3])
	v2, v6, v10, v14 = g(v2.Add(archsimd.LoadUint64x4(&block[0])), v6, v10, v14, nil)
	v1, v5, v9, v13 = g(v1.Add(archsimd.LoadUint64x4(&block[6])), v5, v9, v13, nil)
	v0, v4, v8, v12 = g(v0.Add(archsimd.LoadUint64x4(&block[2])), v4, v8, v12, nil)
	v3, v4, v9, v14 = g(v3.Add(archsimd.LoadUint64x4(&block[1])), v4, v9, v14, nil)
	v2, v7, v8, v13 = g(v2, v7, v8, v13, nil)
	v1, v6, v11, v12 = g(v1.Add(archsimd.LoadUint64x4(&block[7])), v6, v11, v12, &block[5])
	v0, v5, v10, v15 = g(v0.Add(archsimd.LoadUint64x4(&block[4])), v5, v10, v15, nil)
	// round 7
	v3, v7, v11, v15 = g(v3.Add(archsimd.LoadUint64x4(&block[4])), v7, v11, v15, nil)
	v2, v6, v10, v14 = g(v2, v6, v10, v14, nil)
	v1, v5, v9, v13 = g(v1.Add(archsimd.LoadUint64x4(&block[1])), v5, v9, v13, nil)
	v0, v4, v8, v12 = g(v0, v4, v8, v12, &block[5])
	v3, v4, v9, v14 = g(v3.Add(archsimd.LoadUint64x4(&block[8])), v4, v9, v14, nil)
	v2, v7, v8, v13 = g(v2, v7, v8, v13, &block[2])
	v1, v6, v11, v12 = g(v1.Add(archsimd.LoadUint64x4(&block[6])), v6, v11, v12, &block[3])
	v0, v5, v10, v15 = g(v0.Add(archsimd.LoadUint64x4(&block[0])), v5, v10, v15, &block[7])
	// round 8
	v3, v7, v11, v15 = g(v3.Add(archsimd.LoadUint64x4(&block[3])), v7, v11, v15, nil)
	v2, v6, v10, v14 = g(v2, v6, v10, v14, &block[1])
	v1, v5, v9, v13 = g(v1.Add(archsimd.LoadUint64x4(&block[7])), v5, v9, v13, nil)
	v0, v4, v8, v12 = g(v0, v4, v8, v12, nil)
	v3, v4, v9, v14 = g(v3.Add(archsimd.LoadUint64x4(&block[2])), v4, v9, v14, nil)
	v2, v7, v8, v13 = g(v2.Add(archsimd.LoadUint64x4(&block[8])), v7, v8, v13, &block[6])
	v1, v6, v11, v12 = g(v1, v6, v11, v12, &block[4])
	v0, v5, v10, v15 = g(v0.Add(archsimd.LoadUint64x4(&block[5])), v5, v10, v15, &block[0])
	// round 9
	v3, v7, v11, v15 = g(v3.Add(archsimd.LoadUint64x4(&block[0])), v7, v11, v15, &block[8])
	v2, v6, v10, v14 = g(v2, v6, v10, v14, &block[3])
	v1, v5, v9, v13 = g(v1, v5, v9, v13, nil)
	v0, v4, v8, v12 = g(v0.Add(archsimd.LoadUint64x4(&block[6])), v4, v8, v12, nil)
	v3, v4, v9, v14 = g(v3, v4, v9, v14, &block[5])
	v2, v7, v8, v13 = g(v2.Add(archsimd.LoadUint64x4(&block[1])), v7, v8, v13, &block[4])
	v1, v6, v11, v12 = g(v1, v6, v11, v12, &block[7])
	v0, v5, v10, v15 = g(v0, v5, v10, v15, &block[2])
	// round 10
	v3, v7, v11, v15 = g(v3.Add(archsimd.LoadUint64x4(&block[1])), v7, v11, v15, &block[5])
	v2, v6, v10, v14 = g(v2.Add(archsimd.LoadUint64x4(&block[7])), v6, v10, v14, &block[6])
	v1, v5, v9, v13 = g(v1.Add(archsimd.LoadUint64x4(&block[8])), v5, v9, v13, &block[4])
	v0, v4, v8, v12 = g(v0, v4, v8, v12, &block[2])
	v3, v4, v9, v14 = g(v3, v4, v9, v14, &block[0])
	v2, v7, v8, v13 = g(v2.Add(archsimd.LoadUint64x4(&block[3])), v7, v8, v13, nil)
	v1, v6, v11, v12 = g(v1, v6, v11, v12, nil)
	v0, v5, v10, v15 = g(v0, v5, v10, v15, nil)
	// round 11
	v3, v7, v11, v15 = g(v3.Add(archsimd.LoadUint64x4(&block[6])), v7, v11, v15, &block[7])
	v2, v6, v10, v14 = g(v2.Add(archsimd.LoadUint64x4(&block[4])), v6, v10, v14, &block[5])
	v1, v5, v9, v13 = g(v1.Add(archsimd.LoadUint64x4(&block[2])), v5, v9, v13, &block[3])
	v0, v4, v8, v12 = g(v0.Add(archsimd.LoadUint64x4(&block[0])), v4, v8, v12, &block[1])
	v3, v4, v9, v14 = g(v3, v4, v9, v14, nil)
	v2, v7, v8, v13 = g(v2, v7, v8, v13, nil)
	v1, v6, v11, v12 = g(v1, v6, v11, v12, nil)
	v0, v5, v10, v15 = g(v0.Add(archsimd.LoadUint64x4(&block[8])), v5, v10, v15, nil)
	// round 12
	v3, v7, v11, v15 = g(v3, v7, v11, v15, &block[6])
	v2, v6, v10, v14 = g(v2, v6, v10, v14, nil)
	v1, v5, v9, v13 = g(v1.Add(archsimd.LoadUint64x4(&block[4])), v5, v9, v13, &block[8])
	v0, v4, v8, v12 = g(v0, v4, v8, v12, nil)
	v3, v4, v9, v14 = g(v3.Add(archsimd.LoadUint64x4(&block[5])), v4, v9, v14, &block[3])
	v2, v7, v8, v13 = g(v2, v7, v8, v13, &block[7])
	v1, v6, v11, v12 = g(v1.Add(archsimd.LoadUint64x4(&block[0])), v6, v11, v12, &block[2])
	v0, v5, v10, v15 = g(v0.Add(archsimd.LoadUint64x4(&block[1])), v5, v10, v15, nil)

	// finalize; since we're outputting 32-byte hashes, we only need the first
	// four vectors
	v0 = v0.Xor(v8).Xor(archsimd.BroadcastUint64x4(initState[0]))
	v1 = v1.Xor(v9).Xor(archsimd.BroadcastUint64x4(initState[1]))
	v2 = v2.Xor(v10).Xor(archsimd.BroadcastUint64x4(initState[2]))
	v3 = v3.Xor(v11).Xor(archsimd.BroadcastUint64x4(initState[3]))

	// transpose the state vectors into outs; AVX2 has no strided store
	// ("scatter"), so we transpose manually and write them out sequentially
	o0, o1, o2, o3 := transpose4(v0, v1, v2, v3)
	o0.AsUint8x32().Store(&outs[0])
	o1.AsUint8x32().Store(&outs[1])
	o2.AsUint8x32().Store(&outs[2])
	o3.AsUint8x32().Store(&outs[3])
}

// permRotl1 and permRotl3 rotate the four uint64s of a vector left by one and
// three positions, as needed to diagonalize the state in hashBlockAVX2. AVX2
// has no variable 64-bit lane permute, so we use the 32-bit one and move dword
// pairs; a rotation by two positions is a 128-bit lane swap instead, which
// takes an immediate and so needs no index vector.
var (
	permRotl1 = [8]uint32{2, 3, 4, 5, 6, 7, 0, 1}
	permRotl3 = [8]uint32{6, 7, 0, 1, 2, 3, 4, 5}
)

// hashBlockAVX2 hashes a single block. A single hash offers no parallelism, so
// unlike hashBlocksAVX2 the state is held "sideways": four vectors, each holding
// one row of the 4x4 state matrix, and g applies to whole rows. The second half
// of each round mixes diagonals rather than columns, so the rows are rotated
// into place beforehand and back afterwards.
//
// Only the loop-carried chain matters here. The diagonal step needs the rows
// only in relative alignment, so rows (a,b,c,d) are rotated by (3,0,1,2) rather
// than the textbook (0,1,2,3): that leaves b, which g consumes first, unrotated,
// and gives the shuffles to a, which has slack.
//
// out is a parameter so that hashBlock can supply its result buffer directly.
func hashBlockAVX2(out *[32]byte, msg *[64]byte, prefix uint64) {
	// the logical message is a prefix byte plus the 64 message bytes, i.e. 65
	// bytes spanning nine words; the block's remaining seven words are zero
	w := (*[8]uint64)(unsafe.Pointer(msg))
	m0 := w[0]<<8 | prefix
	m1 := w[1]<<8 | w[0]>>56
	m2 := w[2]<<8 | w[1]>>56
	m3 := w[3]<<8 | w[2]>>56
	m4 := w[4]<<8 | w[3]>>56
	m5 := w[5]<<8 | w[4]>>56
	m6 := w[6]<<8 | w[5]>>56
	m7 := w[7]<<8 | w[6]>>56
	m8 := w[7] >> 56

	// because g works on rows, each round's message words have to be gathered
	// into four vectors, which can only be done through memory. Gathering all
	// twelve rounds up front overruns the store buffer, so instead each round
	// gathers the next round's vectors into the other half of this two-entry
	// buffer, interleaving the stores with a round of latency-bound vector work.
	var mv [2][4][4]uint64

	r0 := archsimd.LoadUint64x4((*[4]uint64)(initState[0:4]))
	r1 := archsimd.LoadUint64x4((*[4]uint64)(initState[4:8]))
	r2 := archsimd.LoadUint64x4((*[4]uint64)(initState[8:12]))
	r3 := archsimd.LoadUint64x4((*[4]uint64)(initState[12:16]))
	p1 := archsimd.LoadUint32x8(&permRotl1)
	p3 := archsimd.LoadUint32x8(&permRotl3)

	// each group of four below is one round of BLAKE2b's message schedule, with
	// its references to zero words written out as zeros; the schedule repeats
	// after ten rounds. The first two vectors feed the column step in schedule
	// order; the last two feed the diagonal step, and are written rotated left by
	// three to match the row rotation, so {w, x, y, z} appears as {z, w, x, y}.
	mv[0][0] = [4]uint64{m0, m2, m4, m6}
	mv[0][1] = [4]uint64{m1, m3, m5, m7}
	mv[0][2] = [4]uint64{0, m8, 0, 0}
	mv[0][3] = [4]uint64{0, 0, 0, 0}

	// round 1
	mv[1][0] = [4]uint64{0, m4, 0, 0}
	mv[1][1] = [4]uint64{0, m8, 0, m6}
	mv[1][2] = [4]uint64{m5, m1, m0, 0}
	mv[1][3] = [4]uint64{m3, 0, m2, m7}
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[0][0])), r1, r2, r3, &mv[0][1])
	r0 = r0.AsUint32x8().Permute(p3).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p1).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[0][2])), r1, r2, r3, &mv[0][3])
	r0 = r0.AsUint32x8().Permute(p1).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p3).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)

	// round 2
	mv[0][0] = [4]uint64{0, 0, m5, 0}
	mv[0][1] = [4]uint64{m8, m0, m2, 0}
	mv[0][2] = [4]uint64{0, 0, m3, m7}
	mv[0][3] = [4]uint64{m4, 0, m6, m1}
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[1][0])), r1, r2, r3, &mv[1][1])
	r0 = r0.AsUint32x8().Permute(p3).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p1).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[1][2])), r1, r2, r3, &mv[1][3])
	r0 = r0.AsUint32x8().Permute(p1).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p3).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)

	// round 3
	mv[1][0] = [4]uint64{m7, m3, 0, 0}
	mv[1][1] = [4]uint64{0, m1, 0, 0}
	mv[1][2] = [4]uint64{0, m2, m5, m4}
	mv[1][3] = [4]uint64{m8, m6, 0, m0}
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[0][0])), r1, r2, r3, &mv[0][1])
	r0 = r0.AsUint32x8().Permute(p3).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p1).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[0][2])), r1, r2, r3, &mv[0][3])
	r0 = r0.AsUint32x8().Permute(p1).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p3).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)

	// round 4
	mv[0][0] = [4]uint64{0, m5, m2, 0}
	mv[0][1] = [4]uint64{m0, m7, m4, 0}
	mv[0][2] = [4]uint64{m3, 0, 0, m6}
	mv[0][3] = [4]uint64{0, m1, 0, m8}
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[1][0])), r1, r2, r3, &mv[1][1])
	r0 = r0.AsUint32x8().Permute(p3).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p1).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[1][2])), r1, r2, r3, &mv[1][3])
	r0 = r0.AsUint32x8().Permute(p1).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p3).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)

	// round 5
	mv[1][0] = [4]uint64{m2, m6, m0, m8}
	mv[1][1] = [4]uint64{0, 0, 0, m3}
	mv[1][2] = [4]uint64{m1, m4, m7, 0}
	mv[1][3] = [4]uint64{0, 0, m5, 0}
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[0][0])), r1, r2, r3, &mv[0][1])
	r0 = r0.AsUint32x8().Permute(p3).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p1).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[0][2])), r1, r2, r3, &mv[0][3])
	r0 = r0.AsUint32x8().Permute(p1).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p3).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)

	// round 6
	mv[0][0] = [4]uint64{0, m1, 0, m4}
	mv[0][1] = [4]uint64{m5, 0, 0, 0}
	mv[0][2] = [4]uint64{m8, m0, m6, 0}
	mv[0][3] = [4]uint64{0, m7, m3, m2}
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[1][0])), r1, r2, r3, &mv[1][1])
	r0 = r0.AsUint32x8().Permute(p3).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p1).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[1][2])), r1, r2, r3, &mv[1][3])
	r0 = r0.AsUint32x8().Permute(p1).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p3).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)

	// round 7
	mv[1][0] = [4]uint64{0, m7, 0, m3}
	mv[1][1] = [4]uint64{0, 0, m1, 0}
	mv[1][2] = [4]uint64{m2, m5, 0, m8}
	mv[1][3] = [4]uint64{0, m0, m4, m6}
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[0][0])), r1, r2, r3, &mv[0][1])
	r0 = r0.AsUint32x8().Permute(p3).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p1).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[0][2])), r1, r2, r3, &mv[0][3])
	r0 = r0.AsUint32x8().Permute(p1).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p3).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)

	// round 8
	mv[0][0] = [4]uint64{m6, 0, 0, m0}
	mv[0][1] = [4]uint64{0, 0, m3, m8}
	mv[0][2] = [4]uint64{0, 0, 0, m1}
	mv[0][3] = [4]uint64{m5, m2, m7, m4}
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[1][0])), r1, r2, r3, &mv[1][1])
	r0 = r0.AsUint32x8().Permute(p3).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p1).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[1][2])), r1, r2, r3, &mv[1][3])
	r0 = r0.AsUint32x8().Permute(p1).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p3).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)

	// round 9
	mv[1][0] = [4]uint64{0, m8, m7, m1}
	mv[1][1] = [4]uint64{m2, m4, m6, m5}
	mv[1][2] = [4]uint64{0, 0, 0, m3}
	mv[1][3] = [4]uint64{m0, 0, 0, 0}
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[0][0])), r1, r2, r3, &mv[0][1])
	r0 = r0.AsUint32x8().Permute(p3).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p1).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[0][2])), r1, r2, r3, &mv[0][3])
	r0 = r0.AsUint32x8().Permute(p1).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p3).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)

	// round 10
	mv[0][0] = [4]uint64{m0, m2, m4, m6}
	mv[0][1] = [4]uint64{m1, m3, m5, m7}
	mv[0][2] = [4]uint64{0, m8, 0, 0}
	mv[0][3] = [4]uint64{0, 0, 0, 0}
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[1][0])), r1, r2, r3, &mv[1][1])
	r0 = r0.AsUint32x8().Permute(p3).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p1).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[1][2])), r1, r2, r3, &mv[1][3])
	r0 = r0.AsUint32x8().Permute(p1).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p3).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)

	// round 11
	mv[1][0] = [4]uint64{0, m4, 0, 0}
	mv[1][1] = [4]uint64{0, m8, 0, m6}
	mv[1][2] = [4]uint64{m5, m1, m0, 0}
	mv[1][3] = [4]uint64{m3, 0, m2, m7}
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[0][0])), r1, r2, r3, &mv[0][1])
	r0 = r0.AsUint32x8().Permute(p3).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p1).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[0][2])), r1, r2, r3, &mv[0][3])
	r0 = r0.AsUint32x8().Permute(p1).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p3).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)

	// round 12
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[1][0])), r1, r2, r3, &mv[1][1])
	r0 = r0.AsUint32x8().Permute(p3).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p1).AsUint64x4()
	r3 = r3.Select128FromPair(1, 0, r3)
	r0, r1, r2, r3 = g(r0.Add(archsimd.LoadUint64x4(&mv[1][2])), r1, r2, r3, &mv[1][3])
	// rows 1 and 3 don't contribute to a 32-byte output, so only r0 and r2 have
	// to be rotated back
	r0 = r0.AsUint32x8().Permute(p1).AsUint64x4()
	r2 = r2.AsUint32x8().Permute(p3).AsUint64x4()

	// finalize; we only need the first four state words, which are row 0
	r0.Xor(r2).Xor(archsimd.LoadUint64x4((*[4]uint64)(initState[0:4]))).AsUint8x32().Store(out)
}

func hashBlock(msg *[64]byte, prefix uint64) (out [32]byte) {
	switch {
	case archsimd.X86.AVX2():
		hashBlockAVX2(&out, msg, prefix)
		return out
	default:
		return hashBlockGeneric(msg, prefix)
	}
}

func hashBlocks(outs *[4][32]byte, msgs *[4][64]byte, prefix uint64) {
	switch {
	case archsimd.X86.AVX2():
		hashBlocksAVX2(outs, msgs, prefix)
	default:
		hashBlocksGeneric(outs, msgs, prefix)
	}
}

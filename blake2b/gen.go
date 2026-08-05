//go:build ignore

package main

import (
	"math/bits"

	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

const (
	numLanes        = 4
	numStateVectors = 16
	numBlockWords   = 16
	numStoredWords  = 9 // one prefix byte followed by a 64-byte message
	numRounds       = 12
	messageBytes    = 64
	wordBytes       = 8
	vectorBytes     = numLanes * wordBytes

	// spilledStateVector lives on the stack, freeing its register for temporary
	// values. It must be one of v8..v11 (the c arguments to G) and occur exactly
	// once per half-round. v8 is c in the first column and third diagonal.
	spilledStateVector = 8

	// The stack has one vector per nonzero block word and one spilled state
	// vector. Block words 9..15 are known to be zero and need no storage.
	numStackSlots = numStoredWords + 1
	spillSlot     = numStackSlots - 1
)

type constantReference struct {
	operand *Mem
	offset  int
}

// constantPool packs every constant into one symbol. The generated function
// addresses that symbol through a base register instead of using RIP-relative
// operands: base+disp8 saves three bytes at each of the 288 table references.
type constantPool struct {
	symbol     Mem
	size       int
	references []constantReference
}

// add emits a table and records the operand that refers to it. DATA directives
// must be emitted in ascending address order, so tables are added sequentially.
func (p *constantPool) add(operand *Mem, values []U64) {
	offset := p.size
	*operand = p.symbol.Offset(offset)
	p.references = append(p.references, constantReference{
		operand: operand,
		offset:  offset,
	})
	for _, value := range values {
		DATA(p.size, value)
		p.size += wordBytes
	}
}

// load emits the pool's base address and rewrites its operands relative to that
// base. Saved offsets make repeated calls safe, even though load mutates them.
func (p *constantPool) load() {
	// Centering the base in the symbol keeps every displacement within int8.
	bias := p.size / 2
	base := GP64()
	LEAQ(p.symbol.Offset(bias), base)
	for _, ref := range p.references {
		*ref.operand = Mem{Base: base, Disp: ref.offset - bias}
	}
}

var constants struct {
	constantPool
	foldedState  Mem
	shuffleRot16 Mem
	shuffleRot24 Mem
	shuffleRot32 Mem
	initialState Mem
}

func main() {
	genConstants()
	genHashBlocksAVX2()

	Generate()
}

func genConstants() {
	// All of our messages have the same length and consist of a single block.
	// This means we can precompute the initial state for each hash.
	initialState := []U64{
		// h0..h7: IV xor the parameter block
		0x6a09e667f2bdc928,
		0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b,
		0xa54ff53a5f1d36f1,
		0x510e527fade682d1,
		0x9b05688c2b3e6c1f,
		0x1f83d9abfb41bd6b,
		0x5be0cd19137e2179,
		// v8..v15: IV with the block length and final-block flag applied
		0x6a09e667f3bcc908,
		0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b,
		0xa54ff53a5f1d36f1,
		0x510e527fade68290, // xor'd with 65 (input length)
		0x9b05688c2b3e6c1f,
		0xe07c265404be4294, // xor'd with ~0 (final block)
		0x5be0cd19137e2179,
	}

	// In the first half-round, the a and b vectors are both constants, so the
	// first step of each column's G (a += b) can be precomputed too. These are
	// the values that v0..v3 are actually initialized with; h0..h3 are still
	// needed as vectors by the finalization.
	folded := make([]U64, numLanes)
	for i := range folded {
		folded[i] = initialState[i] + initialState[i+numLanes]
	}

	constants.symbol = GLOBL("blake2b_consts", RODATA|NOPTR)
	constants.add(&constants.foldedState, folded)
	constants.add(&constants.shuffleRot16, rotationShuffle(16))
	constants.add(&constants.shuffleRot24, rotationShuffle(24))
	constants.add(&constants.shuffleRot32, rotationShuffle(32))
	constants.add(&constants.initialState, initialState)
}

// rotationShuffle returns the VPSHUFB indices for rotating each uint64 lane to
// the right by rotation bits.
func rotationShuffle(rotation int) []U64 {
	values := make([]U64, numLanes)
	indices := bits.RotateLeft64(0x0706050403020100, -rotation)
	for i := range values {
		values[i] = U64(indices)
		indices += 0x0808080808080808 // advance each byte to the next lane
	}
	return values
}

type (
	stateVectors [numStateVectors]VecVirtual
	vectorGroup  [numLanes]VecVirtual
	stackSlots   func(int) Mem
)

func genHashBlocksAVX2() {
	TEXT("hashBlocksAVX2", NOSPLIT, "func(outs *[4][32]byte, msgs *[4][64]byte, prefix uint64)")
	Pragma("noescape")
	messages := Mem{Base: Load(Param("msgs"), GP64())}
	outputs := Mem{Base: Load(Param("outs"), GP64())}
	prefix, err := Param("prefix").Resolve()
	if err != nil {
		panic(err)
	}

	state := allocateStateVectors()
	constants.load()
	slots := allocateStackSlots()
	emitMessageTranspose(messages, prefix.Addr, slots, state)

	temporary := state[spilledStateVector]
	spill := slots(spillSlot)
	emitStateInitialization(state, spill)
	for round := 0; round < numRounds; round++ {
		Commentf("Round %d", round+1)
		emitRound(state, permuteMessageWords(slots, round), temporary, spill, round)
	}
	emitFinalization(state, spill)
	emitOutputs(state, outputs)

	Comment("Clear the upper YMM registers to avoid performance penalties")
	VZEROUPPER()
	RET()
}

// allocateStateVectors claims every YMM register up front so that this
// generator, rather than avo's allocator, controls their use.
func allocateStateVectors() (state stateVectors) {
	for i := range state {
		state[i] = YMM()
	}
	return state
}

// allocateStackSlots allocates aligned storage for the transposed message and
// the spilled state vector. Go guarantees only 8-byte stack alignment, so the
// allocation includes enough padding to align its 32-byte vector slots.
//
// Two biased base registers keep every slot within an int8 displacement.
// Besides shorter displacements, general-purpose bases avoid SP's SIB byte.
func allocateStackSlots() stackSlots {
	local := AllocLocal(numStackSlots*vectorBytes + vectorBytes)
	const (
		lowSlotCount      = 6
		lowBias, highBias = 4 * vectorBytes, 10 * vectorBytes
	)

	low, high := GP64(), GP64()
	LEAQ(local.Offset(lowBias+vectorBytes-1), low)
	ANDQ(I8(-vectorBytes), low)
	LEAQ(local.Offset(highBias+vectorBytes-1), high)
	ANDQ(I8(-vectorBytes), high)

	return func(index int) Mem {
		if index < lowSlotCount {
			return Mem{Base: low, Disp: index*vectorBytes - lowBias}
		}
		return Mem{Base: high, Disp: index*vectorBytes - highBias}
	}
}

func emitMessageTranspose(messages, prefix Mem, slots stackSlots, state stateVectors) {
	Comment("Transpose message blocks into the stack")
	// Each block is the message prefixed with a single byte:
	//
	//   block[j] = msg[j]<<8 | msg[j-1]>>56
	//
	// This is an unaligned message load at byte offset 8j-1. Loads at offsets 7
	// and 31 yield words 1..4 and 4..7, which are transposed in registers. Words
	// 0 and 8 need special handling because offset -1 is out of bounds and word
	// 8 contains only the final message byte.
	//
	// Emit word 8 first. Its scalar stores cannot forward to the rounds' vector
	// loads, so putting them first gives them time to reach the cache. Word 0 is
	// built as a vector because it begins the first G's critical path.
	lastByte := GP64()
	for lane := 0; lane < numLanes; lane++ {
		MOVBQZX(messages.Offset(lane*messageBytes+messageBytes-1), lastByte)
		MOVQ(lastByte, slots(numStoredWords-1).Offset(lane*wordBytes))
	}

	words1To4 := vectorGroup{state[0], state[1], state[2], state[3]}
	words4To7 := vectorGroup{state[4], state[5], state[6], state[7]}
	for lane, vector := range words1To4 {
		VMOVDQU(messages.Offset(lane*messageBytes+wordBytes-1), vector)
	}
	for lane, vector := range words4To7 {
		VMOVDQU(messages.Offset(lane*messageBytes+4*wordBytes-1), vector)
	}

	// Gather each lane's first word and shift in the prefix to form block[0].
	word0, word0High := state[8], state[9]
	VMOVQ(messages.Offset(0*messageBytes), word0.AsX())
	VPINSRQ(Imm(1), messages.Offset(1*messageBytes), word0.AsX(), word0.AsX())
	VMOVQ(messages.Offset(2*messageBytes), word0High.AsX())
	VPINSRQ(Imm(1), messages.Offset(3*messageBytes), word0High.AsX(), word0High.AsX())
	VINSERTI128(Imm(1), word0High.AsX(), word0, word0)
	VPSLLQ(Imm(wordBytes), word0, word0)
	VPBROADCASTQ(prefix, word0High)
	VPOR(word0, word0High, word0)
	VMOVDQU(word0, slots(0))

	// In-register transposition is faster than VPGATHERQQ and does not clobber
	// a mask operand.
	temporary := vectorGroup{state[10], state[11], state[12], state[13]}
	transpose4x4(words1To4, temporary, words1To4)
	for i, vector := range words1To4 {
		VMOVDQU(vector, slots(1+i))
	}

	// Word 4 was stored by the first transpose, so omit the duplicate output.
	outputs := words4To7
	outputs[0] = nil
	transpose4x4(words4To7, temporary, outputs)
	for i, vector := range words4To7[1:] {
		VMOVDQU(vector, slots(numLanes+1+i))
	}
}

func emitStateInitialization(state stateVectors, spill Mem) {
	Comment("Round setup")
	// Four parallel blocks consume all 16 YMM registers. v8 therefore lives on
	// the stack while its register serves as the rotate temporary. v8 is always
	// a c argument to G, whose first operation can read it directly from memory.
	for i, vector := range state {
		if i < numLanes {
			// v0..v3 include the first half-round's initial a += b.
			VPBROADCASTQ(constants.foldedState.Offset(i*wordBytes), vector)
		} else {
			VPBROADCASTQ(constants.initialState.Offset(i*wordBytes), vector)
		}
		if i == spilledStateVector {
			VMOVDQU(vector, spill)
		}
	}
}

func emitFinalization(state stateVectors, spill Mem) {
	Comment("Finalize")
	// Only h0..h3 contribute to a 32-byte digest. The xor with the initial state
	// is deferred until after transposition, when one vector can serve all lanes.
	for i, vector := range state[:numLanes] {
		pairedState := i + numStateVectors/2
		if pairedState == spilledStateVector {
			VPXOR(spill, vector, vector)
		} else {
			VPXOR(vector, state[pairedState], vector)
		}
	}
}

func emitOutputs(state stateVectors, outputs Mem) {
	Comment("Transpose state vectors into outs")
	// AVX2 has no scatter instruction, so transpose the four result vectors and
	// write each digest sequentially.
	digests := vectorGroup{state[0], state[1], state[2], state[3]}
	temporary := vectorGroup{state[4], state[5], state[6], state[7]}
	transpose4x4(digests, temporary, digests)

	// Each vector now holds one digest. Apply the deferred h0..h3 xor.
	for i, digest := range digests {
		VPXOR(constants.initialState, digest, digest)
		VMOVDQU(digest, outputs.Offset(i*vectorBytes))
	}
}

// transpose4x4 transposes four vectors of four consecutive uint64s into four
// vectors each holding one uint64 of all four inputs. It clobbers tmp, and out
// may alias in. A nil entry in out means that output is not wanted, and the
// instruction that would produce it is skipped.
func transpose4x4(in, tmp, out vectorGroup) {
	// Interleave each uint64:
	//
	//    in0:  0  1  2  3
	//    in1:  4  5  6  7
	//    in2:  8  9 10 11
	//    in3: 12 13 14 15
	// ->
	//    tmp0:  0  4  2  6
	//    tmp1:  1  5  3  7
	//    tmp2:  8 12 10 14
	//    tmp3:  9 13 11 15
	VPUNPCKLQDQ(in[1], in[0], tmp[0])
	VPUNPCKHQDQ(in[1], in[0], tmp[1])
	VPUNPCKLQDQ(in[3], in[2], tmp[2])
	VPUNPCKHQDQ(in[3], in[2], tmp[3])
	// Interleave groups of two uint64s:
	//
	// ->
	//    out0:  0  4  8 12
	//    out1:  1  5  9 13
	//    out2:  2  6 10 14
	//    out3:  3  7 11 15
	if out[0] != nil {
		VINSERTI128(Imm(1), tmp[2].AsX(), tmp[0], out[0])
	}
	if out[1] != nil {
		VINSERTI128(Imm(1), tmp[3].AsX(), tmp[1], out[1])
	}
	if out[2] != nil {
		VPERM2I128(Imm(0x31), tmp[2], tmp[0], out[2])
	}
	if out[3] != nil {
		VPERM2I128(Imm(0x31), tmp[3], tmp[1], out[3])
	}
}

// gStateIndices lists the state vectors mixed by each G: first the four
// columns, then the four diagonals. Each vector always has the same G argument
// position, which is what makes it possible to spill one of the c vectors.
var gStateIndices = [8][numLanes]int{
	{0, 4, 8, 12},
	{1, 5, 9, 13},
	{2, 6, 10, 14},
	{3, 7, 11, 15},
	{0, 5, 10, 15},
	{1, 6, 11, 12},
	{2, 7, 8, 13},
	{3, 4, 9, 14},
}

// gEmissionOrder determines the order of the four Gs in each half-round. The
// first diagonal depends on the column whose b vector becomes ready first.
var gEmissionOrder = [2][numLanes]int{
	{0, 1, 2, 3},
	{3, 0, 1, 2},
}

type instruction func()

func (step instruction) emit() {
	if step != nil {
		step()
	}
}

type instructionSequence []instruction

func (sequence instructionSequence) emit() {
	for _, step := range sequence {
		step.emit()
	}
}

type gSchedule struct {
	pre  instruction
	body instructionSequence
	tail instructionSequence
}

// emitRound emits eight Gs as two half-rounds. The four Gs in each half-round
// are independent, so their instructions are staggered to keep ready work from
// sitting behind instructions whose operands are not ready yet.
func emitRound(state stateVectors, message messageWords, temporary VecVirtual, spill Mem, round int) {
	for half := 0; half < 2; half++ {
		// The initial a += b is already present in constants.foldedState. In the
		// final half-round, b is never read again, so its final updates are omitted.
		skipInitialAB := round == 0 && half == 0
		discardFinalB := round == numRounds-1 && half == 1

		var schedules [numLanes]gSchedule
		spilledSchedule := -1
		for scheduleIndex, halfIndex := range gEmissionOrder[half] {
			gIndex := half*numLanes + halfIndex
			indices := gStateIndices[gIndex]
			gState := vectorGroup{
				state[indices[0]],
				state[indices[1]],
				state[indices[2]],
				state[indices[3]],
			}
			gMessage := [2]messageWord{message[2*gIndex], message[2*gIndex+1]}
			schedules[scheduleIndex] = scheduleG(
				gState,
				gMessage,
				temporary,
				spill,
				skipInitialAB,
				discardFinalB,
			)
			if gState[2] == temporary {
				spilledSchedule = scheduleIndex
			}
		}
		if spilledSchedule < 0 {
			panic("half-round has no spilled c vector")
		}

		for _, schedule := range schedules {
			schedule.pre.emit()
		}
		interleave(schedules)

		// The spilled c occupies the temporary register until the first step of
		// its tail writes it back. Emit that tail before any other G reuses tmp.
		schedules[spilledSchedule].tail.emit()
		for i, schedule := range schedules {
			if i != spilledSchedule {
				schedule.tail.emit()
			}
		}
	}
}

// gSkew is how many instruction slots separate adjacent Gs. Lockstep emission
// makes all four Gs demand the same execution port in the same cycle, while
// emitting whole Gs serially places stalled work ahead of ready work.
const gSkew = 2

// interleave emits the bodies of four Gs with each one staggered by gSkew. A nil
// instruction emits nothing but retains its place in the schedule.
func interleave(schedules [numLanes]gSchedule) {
	longest := 0
	for _, schedule := range schedules {
		longest = max(longest, len(schedule.body))
	}

	for slot := 0; slot < longest+(len(schedules)-1)*gSkew; slot++ {
		for i, schedule := range schedules {
			instructionIndex := slot - i*gSkew
			if 0 <= instructionIndex && instructionIndex < len(schedule.body) {
				schedule.body[instructionIndex].emit()
			}
		}
	}
}

func rotateRight63(vector, temporary VecVirtual) {
	// Rotate-right 63 is rotate-left 1. Express the left shift as an add so it
	// can also issue on port 5; vector-lane addition cannot carry between lanes.
	VPSRLQ(Imm(63), vector, temporary)
	VPADDQ(vector, vector, vector)
	VPOR(vector, temporary, vector)
}

type messageWord struct {
	address Mem
	present bool
}

type messageWords [numBlockWords]messageWord

func (word messageWord) addTo(vector VecVirtual) instruction {
	if !word.present {
		return nil
	}
	return func() { VPADDQ(word.address, vector, vector) }
}

// scheduleG returns G as three instruction groups so emitRound can interleave
// four independent Gs. pre adds the first message word before interleaving;
// body is interleaved; tail must wait until all bodies finish because it reuses
// the temporary register.
//
// Each of G's two a updates adds both b and a message word. Since addition is
// associative, each message word is added as soon as a is available, removing
// it from the critical path through the freshly rotated b.
func scheduleG(
	state vectorGroup,
	message [2]messageWord,
	temporary VecVirtual,
	spill Mem,
	skipInitialAB bool,
	discardFinalB bool,
) (schedule gSchedule) {
	a, b, c, d := state[0], state[1], state[2], state[3]

	var addAB instruction
	if !skipInitialAB {
		addAB = func() { VPADDQ(b, a, a) }
	}

	// A spilled c is read directly from the stack and then occupies temporary
	// until its value is written back in the tail.
	addCD := func() { VPADDQ(c, d, c) }
	if c == temporary {
		addCD = func() { VPADDQ(spill, d, c) }
	}

	schedule.pre = message[0].addTo(a)
	schedule.body = instructionSequence{
		addAB,
		func() { VPXOR(d, a, d) },
		message[1].addTo(a),
		func() { VPSHUFB(constants.shuffleRot32, d, d) },
		addCD,
		func() { VPXOR(b, c, b) },
		func() { VPSHUFB(constants.shuffleRot24, b, b) },
		func() { VPADDQ(b, a, a) },
		func() { VPXOR(d, a, d) },
		func() { VPSHUFB(constants.shuffleRot16, d, d) },
		func() { VPADDQ(c, d, c) },
	}
	if !discardFinalB {
		schedule.body = append(schedule.body, func() { VPXOR(b, c, b) })
	}
	if c == temporary {
		schedule.tail = append(schedule.tail, func() { VMOVDQU(c, spill) })
	}
	if !discardFinalB {
		schedule.tail = append(schedule.tail, func() { rotateRight63(b, temporary) })
	}
	return schedule
}

// Each round uses a different permutation of the message words. Since the
// compression function is fully inlined, it is enough to permute addresses.
var messagePermutations = [numRounds][numBlockWords]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
}

func permuteMessageWords(slots stackSlots, round int) (words messageWords) {
	for i, wordIndex := range messagePermutations[round] {
		if wordIndex < numStoredWords {
			words[i] = messageWord{address: slots(wordIndex), present: true}
		}
		// Words 9..15 are zero because the input block is only 65 bytes.
	}
	return words
}

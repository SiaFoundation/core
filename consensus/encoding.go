package consensus

import (
	"time"

	"go.sia.tech/core/types"
)

// EncodeTo implements types.EncoderTo.
func (sa *StateAccumulator) EncodeTo(e *types.Encoder) {
	e.WriteUint64(sa.NumLeaves)
	for i, root := range sa.Trees {
		if sa.HasTreeAtHeight(i) {
			e.WriteHash(root)
		}
	}
}

// DecodeFrom implements types.DecoderFrom.
func (sa *StateAccumulator) DecodeFrom(d *types.Decoder) {
	sa.NumLeaves = d.ReadUint64()
	for i := range sa.Trees {
		if sa.HasTreeAtHeight(i) {
			sa.Trees[i] = d.ReadHash()
		}
	}
}

// EncodeTo implements types.EncoderTo.
func (ha *HistoryAccumulator) EncodeTo(e *types.Encoder) {
	(*StateAccumulator)(ha).EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (ha *HistoryAccumulator) DecodeFrom(d *types.Decoder) {
	(*StateAccumulator)(ha).DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (vc *ValidationContext) EncodeTo(e *types.Encoder) {
	e.WriteChainIndex(vc.Index)
	vc.State.EncodeTo(e)
	vc.History.EncodeTo(e)
	for _, ts := range vc.PrevTimestamps {
		e.WriteTime(ts)
	}
	e.WriteWork(vc.TotalWork)
	e.WriteWork(vc.Difficulty)
	e.WriteWork(vc.OakWork)
	e.WriteUint64(uint64(vc.OakTime))
	e.WriteTime(vc.GenesisTimestamp)
	e.WriteCurrency(vc.SiafundPool)
	e.WriteAddress(vc.FoundationAddress)
}

// DecodeFrom implements types.DecoderFrom.
func (vc *ValidationContext) DecodeFrom(d *types.Decoder) {
	vc.Index = d.ReadChainIndex()
	vc.State.DecodeFrom(d)
	vc.History.DecodeFrom(d)
	for i := range vc.PrevTimestamps {
		vc.PrevTimestamps[i] = d.ReadTime()
	}
	vc.TotalWork = d.ReadWork()
	vc.Difficulty = d.ReadWork()
	vc.OakWork = d.ReadWork()
	vc.OakTime = time.Duration(d.ReadUint64())
	vc.GenesisTimestamp = d.ReadTime()
	vc.SiafundPool = d.ReadCurrency()
	vc.FoundationAddress = d.ReadAddress()
}

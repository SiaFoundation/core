package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strings"
	"testing"
	"time"

	"go.sia.tech/core/blake2b"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

func testnet() (*Network, types.Block) {
	n := &Network{
		Name:            "testnet",
		InitialCoinbase: types.Siacoins(300000),
		MinimumCoinbase: types.Siacoins(300000),
		InitialTarget:   types.BlockID{0xFF},
		BlockInterval:   10 * time.Millisecond,
		MaturityDelay:   5,
	}
	n.HardforkDevAddr.Height = 1
	n.HardforkTax.Height = 2
	n.HardforkStorageProof.Height = 3
	n.HardforkOak.Height = 4
	n.HardforkOak.FixHeight = 5
	n.HardforkOak.GenesisTimestamp = time.Unix(1618033988, 0) // φ
	n.HardforkASIC.Height = 6
	n.HardforkASIC.OakTime = 10000 * time.Second
	n.HardforkASIC.OakTarget = n.InitialTarget
	n.HardforkASIC.NonceFactor = 1009
	n.HardforkFoundation.Height = 7
	n.HardforkFoundation.PrimaryAddress = types.AnyoneCanSpend().Address()
	n.HardforkFoundation.FailsafeAddress = types.VoidAddress
	n.HardforkV2.AllowHeight = 1000
	n.HardforkV2.RequireHeight = 2000
	n.HardforkV2.FinalCutHeight = 3000
	b := types.Block{Timestamp: n.HardforkOak.GenesisTimestamp}
	return n, b
}

type consensusDB struct {
	sces     map[types.SiacoinOutputID]types.SiacoinElement
	sfes     map[types.SiafundOutputID]types.SiafundElement
	fces     map[types.FileContractID]types.FileContractElement
	v2fces   map[types.FileContractID]types.V2FileContractElement
	blockIDs []types.BlockID
}

func (db *consensusDB) applyBlock(au ApplyUpdate) {
	for id, sce := range db.sces {
		au.UpdateElementProof(&sce.StateElement)
		db.sces[id] = sce.Move()
	}
	for id, sfe := range db.sfes {
		au.UpdateElementProof(&sfe.StateElement)
		db.sfes[id] = sfe.Move()
	}
	for id, fce := range db.fces {
		au.UpdateElementProof(&fce.StateElement)
		db.fces[id] = fce.Move()
	}
	for id, fce := range db.v2fces {
		au.UpdateElementProof(&fce.StateElement)
		db.v2fces[id] = fce.Move()
	}
	for _, sce := range au.sces {
		if sce.Spent {
			delete(db.sces, sce.SiacoinElement.ID)
		} else {
			db.sces[sce.SiacoinElement.ID] = sce.SiacoinElement.Copy()
		}
	}
	for _, sfe := range au.sfes {
		if sfe.Spent {
			delete(db.sfes, sfe.SiafundElement.ID)
		} else {
			db.sfes[sfe.SiafundElement.ID] = sfe.SiafundElement.Copy()
		}
	}
	for _, fce := range au.fces {
		if fce.Created {
			db.fces[fce.FileContractElement.ID] = fce.FileContractElement.Copy()
		} else if fce.Revision != nil {
			fce.FileContractElement.FileContract = *fce.Revision
			db.fces[fce.FileContractElement.ID] = fce.FileContractElement.Copy()
		} else if fce.Resolved {
			delete(db.fces, fce.FileContractElement.ID)
		}
	}
	for _, v2fce := range au.v2fces {
		if v2fce.Created {
			db.v2fces[v2fce.V2FileContractElement.ID] = v2fce.V2FileContractElement.Copy()
		} else if v2fce.Revision != nil {
			v2fce.V2FileContractElement.V2FileContract = *v2fce.Revision
			db.v2fces[v2fce.V2FileContractElement.ID] = v2fce.V2FileContractElement.Copy()
		} else if v2fce.Resolution != nil {
			delete(db.v2fces, v2fce.V2FileContractElement.ID)
		}
	}
	db.blockIDs = append(db.blockIDs, au.cie.ID)
}

func (db *consensusDB) revertBlock(ru RevertUpdate) {
	for _, sce := range ru.sces {
		if sce.Spent {
			db.sces[sce.SiacoinElement.ID] = sce.SiacoinElement.Copy()
		} else {
			delete(db.sces, sce.SiacoinElement.ID)
		}
	}
	for _, sfe := range ru.sfes {
		if sfe.Spent {
			db.sfes[sfe.SiafundElement.ID] = sfe.SiafundElement.Copy()
		} else {
			delete(db.sfes, sfe.SiafundElement.ID)
		}
	}
	for _, fce := range ru.fces {
		if fce.Created {
			delete(db.fces, fce.FileContractElement.ID)
		} else if fce.Revision != nil {
			db.fces[fce.FileContractElement.ID] = fce.FileContractElement.Copy()
		} else if fce.Resolved {
			db.fces[fce.FileContractElement.ID] = fce.FileContractElement.Copy()
		}
	}
	for _, v2fce := range ru.v2fces {
		if v2fce.Created {
			delete(db.v2fces, v2fce.V2FileContractElement.ID)
		} else if v2fce.Revision != nil {
			db.v2fces[v2fce.V2FileContractElement.ID] = v2fce.V2FileContractElement.Copy()
		} else if v2fce.Resolution != nil {
			db.v2fces[v2fce.V2FileContractElement.ID] = v2fce.V2FileContractElement.Copy()
		}
	}

	for id, sce := range db.sces {
		ru.UpdateElementProof(&sce.StateElement)
		db.sces[id] = sce.Copy()
	}
	for id, sfe := range db.sfes {
		ru.UpdateElementProof(&sfe.StateElement)
		db.sfes[id] = sfe.Copy()
	}
	for id, fce := range db.fces {
		ru.UpdateElementProof(&fce.StateElement)
		db.fces[id] = fce.Copy()
	}
	for id, fce := range db.v2fces {
		ru.UpdateElementProof(&fce.StateElement)
		db.v2fces[id] = fce.Copy()
	}
}

func (db *consensusDB) supplementTipBlock(b types.Block) (bs V1BlockSupplement) {
	bs = V1BlockSupplement{
		Transactions: make([]V1TransactionSupplement, len(b.Transactions)),
	}
	for i, txn := range b.Transactions {
		ts := &bs.Transactions[i]
		for _, sci := range txn.SiacoinInputs {
			if sce, ok := db.sces[sci.ParentID]; ok {
				ts.SiacoinInputs = append(ts.SiacoinInputs, sce.Copy())
			}
		}
		for _, sfi := range txn.SiafundInputs {
			if sfe, ok := db.sfes[sfi.ParentID]; ok {
				ts.SiafundInputs = append(ts.SiafundInputs, sfe.Copy())
			}
		}
		for _, fcr := range txn.FileContractRevisions {
			if fce, ok := db.fces[fcr.ParentID]; ok {
				ts.RevisedFileContracts = append(ts.RevisedFileContracts, fce.Copy())
			}
		}
		for _, sp := range txn.StorageProofs {
			if fce, ok := db.fces[sp.ParentID]; ok {
				ts.StorageProofs = append(ts.StorageProofs, V1StorageProofSupplement{
					FileContract: fce.Copy(),
					WindowID:     db.blockIDs[fce.FileContract.WindowStart],
				})
			}
		}
	}
	return bs
}

func (db *consensusDB) ancestorTimestamp(types.BlockID) time.Time {
	return time.Time{}
}

func newConsensusDB(n *Network, genesisBlock types.Block) (*consensusDB, State) {
	db := &consensusDB{
		sces:   make(map[types.SiacoinOutputID]types.SiacoinElement),
		sfes:   make(map[types.SiafundOutputID]types.SiafundElement),
		fces:   make(map[types.FileContractID]types.FileContractElement),
		v2fces: make(map[types.FileContractID]types.V2FileContractElement),
	}
	cs, au := ApplyBlock(n.GenesisState(), genesisBlock, db.supplementTipBlock(genesisBlock), time.Time{})
	db.applyBlock(au)
	return db, cs
}

func findBlockNonce(cs State, b *types.Block) {
	// ensure nonce meets factor requirement
	for b.Nonce%cs.NonceFactor() != 0 {
		b.Nonce++
	}
	for b.ID().CmpWork(cs.PoWTarget()) < 0 {
		b.Nonce += cs.NonceFactor()
	}
}

func findHeaderNonce(cs State, b *types.BlockHeader) {
	// ensure nonce meets factor requirement
	for b.Nonce%cs.NonceFactor() != 0 {
		b.Nonce++
	}
	for b.ID().CmpWork(cs.PoWTarget()) < 0 {
		b.Nonce += cs.NonceFactor()
	}
}

func deepCopyBlock(b types.Block) (b2 types.Block) {
	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	types.V2Block(b).EncodeTo(e)
	e.Flush()
	d := types.NewBufDecoder(buf.Bytes())
	(*types.V2Block)(&b2).DecodeFrom(d)
	return
}

// copied from rhp/v2 to avoid import cycle
func prepareContractFormation(renterPubKey types.PublicKey, hostKey types.PublicKey, renterPayout, hostCollateral types.Currency, endHeight uint64, windowSize uint64, refundAddr types.Address) types.FileContract {
	taxAdjustedPayout := func(target types.Currency) types.Currency {
		guess := target.Mul64(1000).Div64(961)
		mod64 := func(c types.Currency, v uint64) types.Currency {
			var r uint64
			if c.Hi < v {
				_, r = bits.Div64(c.Hi, c.Lo, v)
			} else {
				_, r = bits.Div64(0, c.Hi, v)
				_, r = bits.Div64(r, c.Lo, v)
			}
			return types.NewCurrency64(r)
		}
		sfc := (State{}).SiafundCount()
		tm := mod64(target, sfc)
		gm := mod64(guess, sfc)
		if gm.Cmp(tm) < 0 {
			guess = guess.Sub(types.NewCurrency64(sfc))
		}
		return guess.Add(tm).Sub(gm)
	}
	uc := types.UnlockConditions{
		PublicKeys: []types.UnlockKey{
			{Algorithm: types.SpecifierEd25519, Key: renterPubKey[:]},
			{Algorithm: types.SpecifierEd25519, Key: hostKey[:]},
		},
		SignaturesRequired: 2,
	}
	hostPayout := hostCollateral
	payout := taxAdjustedPayout(renterPayout.Add(hostPayout))
	return types.FileContract{
		Filesize:       0,
		FileMerkleRoot: types.Hash256{},
		WindowStart:    endHeight,
		WindowEnd:      endHeight + windowSize,
		Payout:         payout,
		UnlockHash:     uc.UnlockHash(),
		RevisionNumber: 0,
		ValidProofOutputs: []types.SiacoinOutput{
			{Value: renterPayout, Address: refundAddr},
			{Value: hostPayout, Address: types.VoidAddress},
		},
		MissedProofOutputs: []types.SiacoinOutput{
			{Value: renterPayout, Address: refundAddr},
			{Value: hostPayout, Address: types.VoidAddress},
			{Value: types.ZeroCurrency, Address: types.VoidAddress},
		},
	}
}

func TestValidateBlock(t *testing.T) {
	n, genesisBlock := testnet()

	n.HardforkTax.Height = 0
	n.HardforkFoundation.Height = 0
	n.InitialTarget = types.BlockID{0xFF}

	giftPrivateKey := types.GeneratePrivateKey()
	renterPrivateKey := types.GeneratePrivateKey()
	hostPrivateKey := types.GeneratePrivateKey()
	giftPublicKey := giftPrivateKey.PublicKey()
	renterPublicKey := renterPrivateKey.PublicKey()
	hostPublicKey := hostPrivateKey.PublicKey()
	giftAddress := types.StandardUnlockHash(giftPublicKey)
	giftAmountSC := types.Siacoins(100)
	giftAmountSF := uint64(100)
	giftFC := prepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), 100, 100, types.VoidAddress)
	giftTxn := types.Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: giftAddress, Value: giftAmountSC},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Address: giftAddress, Value: giftAmountSF},
		},
		FileContracts: []types.FileContract{giftFC},
	}
	genesisBlock.Transactions = []types.Transaction{giftTxn}
	db, cs := newConsensusDB(n, genesisBlock)

	signTxn := func(txn *types.Transaction) {
		appendSig := func(key types.PrivateKey, pubkeyIndex uint64, parentID types.Hash256) {
			sig := key.SignHash(cs.WholeSigHash(*txn, parentID, pubkeyIndex, 0, nil))
			txn.Signatures = append(txn.Signatures, types.TransactionSignature{
				ParentID:       parentID,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
				PublicKeyIndex: pubkeyIndex,
				Signature:      sig[:],
			})
		}
		for i := range txn.SiacoinInputs {
			appendSig(giftPrivateKey, 0, types.Hash256(txn.SiacoinInputs[i].ParentID))
		}
		for i := range txn.SiafundInputs {
			appendSig(giftPrivateKey, 0, types.Hash256(txn.SiafundInputs[i].ParentID))
		}
		for i := range txn.FileContractRevisions {
			appendSig(renterPrivateKey, 0, types.Hash256(txn.FileContractRevisions[i].ParentID))
			appendSig(hostPrivateKey, 1, types.Hash256(txn.FileContractRevisions[i].ParentID))
		}
	}

	// construct a block that can be used to test all aspects of validation
	fc := prepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), cs.Index.Height+1, 100, types.VoidAddress)

	revision := giftFC
	revision.RevisionNumber++
	revision.WindowStart = cs.Index.Height + 1
	revision.WindowEnd = revision.WindowStart + 100

	minerFee := types.Siacoins(1)

	b := types.Block{
		ParentID:  genesisBlock.ID(),
		Timestamp: types.CurrentTimestamp(),
		Transactions: []types.Transaction{
			{
				SiacoinInputs: []types.SiacoinInput{{
					ParentID:         giftTxn.SiacoinOutputID(0),
					UnlockConditions: types.StandardUnlockConditions(giftPublicKey),
				}},
				SiafundInputs: []types.SiafundInput{{
					ParentID:         giftTxn.SiafundOutputID(0),
					ClaimAddress:     types.VoidAddress,
					UnlockConditions: types.StandardUnlockConditions(giftPublicKey),
				}},
				SiacoinOutputs: []types.SiacoinOutput{
					{Value: giftAmountSC.Sub(fc.Payout).Sub(minerFee), Address: giftAddress},
				},
				SiafundOutputs: []types.SiafundOutput{
					{Value: giftAmountSF / 2, Address: giftAddress},
					{Value: giftAmountSF / 2, Address: types.VoidAddress},
				},
				FileContracts: []types.FileContract{fc},
				FileContractRevisions: []types.FileContractRevision{
					{
						ParentID: giftTxn.FileContractID(0),
						UnlockConditions: types.UnlockConditions{
							PublicKeys:         []types.UnlockKey{renterPublicKey.UnlockKey(), hostPublicKey.UnlockKey()},
							SignaturesRequired: 2,
						},
						FileContract: revision,
					},
				},
				MinerFees: []types.Currency{minerFee},
			},
		},
		MinerPayouts: []types.SiacoinOutput{{
			Address: types.VoidAddress,
			Value:   cs.BlockReward().Add(minerFee),
		}},
	}
	b.Transactions[0].FileContracts[0].FileMerkleRoot = types.HashBytes(make([]byte, 65))
	b.Transactions = append(b.Transactions, types.Transaction{
		StorageProofs: []types.StorageProof{{
			ParentID: b.Transactions[0].FileContractID(0),
		}},
	})

	// block should be valid
	validBlock := deepCopyBlock(b)
	signTxn(&validBlock.Transactions[0])
	findBlockNonce(cs, &validBlock)
	if err := ValidateBlock(cs, validBlock, db.supplementTipBlock(validBlock)); err != nil {
		t.Fatal(err)
	}

	// clear signatures to avoid false positives
	validBlock.Transactions[0].Signatures = nil

	// tests with correct signatures
	{
		tests := []struct {
			errString string
			corrupt   func(*types.Block)
		}{
			{
				"block exceeds maximum weight",
				func(b *types.Block) {
					data := make([]byte, cs.MaxBlockWeight())
					b.Transactions = append(b.Transactions, types.Transaction{
						ArbitraryData: [][]byte{data},
					})
				},
			},
			{
				"block has wrong parent ID",
				func(b *types.Block) {
					b.ParentID[0] ^= 255
				},
			},
			{
				"block has timestamp too far in the past",
				func(b *types.Block) {
					b.Timestamp = cs.PrevTimestamps[0].AddDate(-1, 0, 0)
				},
			},
			{
				"miner payout sum (0 SC) does not match block reward + fees (300.001 KS)",
				func(b *types.Block) {
					b.MinerPayouts = nil
				},
			},
			{
				"miner payout has zero value",
				func(b *types.Block) {
					b.MinerPayouts = []types.SiacoinOutput{{
						Address: types.VoidAddress,
						Value:   types.ZeroCurrency,
					}}
				},
			},
			{
				"miner payout sum (150 KS) does not match block reward + fees (300.001 KS)",
				func(b *types.Block) {
					b.MinerPayouts = []types.SiacoinOutput{{
						Address: types.VoidAddress,
						Value:   cs.BlockReward().Div64(2),
					}}
				},
			},
			{
				"miner payouts overflow",
				func(b *types.Block) {
					b.MinerPayouts = []types.SiacoinOutput{
						{Address: types.VoidAddress, Value: types.MaxCurrency},
						{Address: types.VoidAddress, Value: types.MaxCurrency},
					}
				},
			},
			{
				"transaction outputs exceed inputs",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiacoinOutputs = []types.SiacoinOutput{
						{Address: types.VoidAddress, Value: types.MaxCurrency},
						{Address: types.VoidAddress, Value: types.MaxCurrency},
					}
				},
			},
			{
				"transaction outputs exceed inputs",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiafundOutputs = []types.SiafundOutput{
						{Address: types.VoidAddress, Value: 10001},
					}
				},
			},
			{
				"transaction creates a zero-valued output",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					for i := range txn.SiacoinOutputs {
						txn.SiacoinOutputs[i].Value = types.ZeroCurrency
					}
					txn.SiacoinInputs = nil
					txn.FileContracts = nil
				},
			},
			{
				"transaction creates a zero-valued output",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					for i := range txn.SiafundOutputs {
						txn.SiafundOutputs[i].Value = 0
					}
					txn.SiafundInputs = nil
				},
			},
			{
				"transaction fee has zero value",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.MinerFees = append(txn.MinerFees, types.ZeroCurrency)
				},
			},
			{
				"transaction fees overflow",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.MinerFees = append(txn.MinerFees, types.MaxCurrency)
					txn.MinerFees = append(txn.MinerFees, types.MaxCurrency)
				},
			},
			{
				"siacoin inputs (100 SC) do not equal outputs (100.000000000000000000000001 SC)",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Add(types.NewCurrency64(1))
				},
			},
			{
				"siacoin inputs (100 SC) do not equal outputs (99.999999999999999999999999 SC)",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Sub(types.NewCurrency64(1))
				},
			},
			{
				"siafund inputs (100) do not equal outputs (101)",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiafundOutputs[0].Value++
				},
			},
			{
				"siafund inputs (100) do not equal outputs (99)",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiafundOutputs[0].Value--
				},
			},
			{
				fmt.Sprintf("transaction spends siacoin input %v more than once", giftTxn.SiacoinOutputID(0)),
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiacoinInputs = append(txn.SiacoinInputs, txn.SiacoinInputs[0])
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Add(giftAmountSC)
				},
			},
			{
				fmt.Sprintf("transaction spends siafund input %v more than once", giftTxn.SiafundOutputID(0)),
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiafundInputs = append(txn.SiafundInputs, txn.SiafundInputs[0])
					txn.SiafundOutputs[0].Value += giftAmountSF
				},
			},
			{
				"siacoin input 0 claims incorrect unlock conditions",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiacoinInputs[0].UnlockConditions.PublicKeys[0].Key[0] ^= 255
				},
			},
			{
				"siafund input 0 claims incorrect unlock conditions",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiafundInputs[0].UnlockConditions.PublicKeys[0].Key[0] ^= 255
				},
			},
			{
				"improperly-encoded FoundationAddressUpdate",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.ArbitraryData = append(txn.ArbitraryData, append(types.SpecifierFoundation[:], []byte{255, 255, 255, 255, 255}...))
				},
			},
			{
				"uninitialized FoundationAddressUpdate",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					var buf bytes.Buffer
					e := types.NewEncoder(&buf)
					types.FoundationAddressUpdate{}.EncodeTo(e)
					e.Flush()
					txn.ArbitraryData = append(txn.ArbitraryData, append(types.SpecifierFoundation[:], buf.Bytes()...))
				},
			},
			{
				"unsigned FoundationAddressUpdate",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					var buf bytes.Buffer
					e := types.NewEncoder(&buf)
					types.FoundationAddressUpdate{
						NewPrimary:  giftAddress,
						NewFailsafe: giftAddress,
					}.EncodeTo(e)
					e.Flush()
					txn.ArbitraryData = append(txn.ArbitraryData, append(types.SpecifierFoundation[:], buf.Bytes()...))
				},
			},
			{
				"file contract 0 has window that starts in the past",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContracts[0].WindowStart = 0
				},
			},
			{
				"storage proof 0 references nonexistent file contract",
				func(b *types.Block) {
					txn := &b.Transactions[1]
					txn.StorageProofs[0].ParentID = types.FileContractID{}
				},
			},
			{
				"storage proof 0 cannot be submitted until after window start (100)",
				func(b *types.Block) {
					b.Transactions[0].FileContracts[0].WindowStart = 100
					b.Transactions[1].StorageProofs[0].ParentID = b.Transactions[0].FileContractID(0)
				},
			},
			{
				"file contract revision 0 conflicts with previous proof or revision",
				func(b *types.Block) {
					rev := revision
					rev.RevisionNumber++
					b.Transactions = append(b.Transactions, types.Transaction{
						FileContractRevisions: []types.FileContractRevision{{
							ParentID:     b.Transactions[1].StorageProofs[0].ParentID,
							FileContract: rev,
						}},
					})
				},
			},
			{
				fmt.Sprintf("storage proof 1 resolves contract (%v) already resolved by storage proof 0", b.Transactions[0].FileContractID(0)),
				func(b *types.Block) {
					txn := &b.Transactions[1]
					txn.StorageProofs = append(txn.StorageProofs, txn.StorageProofs[0])
				},
			},
			{
				fmt.Sprintf("storage proof 0 conflicts with previous proof (in %v)", b.Transactions[1].ID()),
				func(b *types.Block) {
					b.Transactions = append(b.Transactions, types.Transaction{
						StorageProofs: b.Transactions[1].StorageProofs,
					})
				},
			},
			{
				fmt.Sprintf("storage proof 0 conflicts with previous proof (in %v)", b.Transactions[1].ID()),
				func(b *types.Block) {
					b.Transactions = append(b.Transactions, types.Transaction{
						StorageProofs: b.Transactions[1].StorageProofs,
					})
				},
			},
			{
				"window that ends before it begins",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContracts[0].WindowStart = txn.FileContracts[0].WindowEnd
				},
			},
			{
				"valid payout that does not equal missed payout",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContracts[0].ValidProofOutputs[0].Value = txn.FileContracts[0].ValidProofOutputs[0].Value.Add(types.Siacoins(1))
				},
			},
			{
				"payout with incorrect tax",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Add(types.Siacoins(1))
					txn.FileContracts[0].Payout = txn.FileContracts[0].Payout.Sub(types.Siacoins(1))
				},
			},
			{
				"revises nonexistent file contract",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContractRevisions[0].ParentID[0] ^= 255
				},
			},
			{
				"file contract revision 0 has timelocked parent",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContractRevisions[0].UnlockConditions.Timelock = cs.Index.Height + 10
				},
			},
			{
				"file contract revision 0 has window that starts in the past",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContractRevisions[0].WindowStart = cs.Index.Height
				},
			},
			{
				"file contract revision 0 has window that ends before it begins",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContractRevisions[0].WindowStart = txn.FileContractRevisions[0].WindowEnd
				},
			},
			{
				"file contract revision 0 does not have a higher revision number than its parent",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContractRevisions[0].RevisionNumber = 0
					b.Transactions = b.Transactions[:1]
				},
			},
			{
				"file contract revision 0 claims incorrect unlock conditions",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContractRevisions[0].UnlockConditions.PublicKeys[0].Key[0] ^= 255
				},
			},
			{
				"file contract revision 0 changes valid payout sum",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContractRevisions[0].ValidProofOutputs = append(txn.FileContractRevisions[0].ValidProofOutputs, types.SiacoinOutput{
						Value: types.Siacoins(1),
					})
				},
			},
			{
				"file contract revision 0 changes missed payout sum",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContractRevisions[0].MissedProofOutputs = append(txn.FileContractRevisions[0].MissedProofOutputs, types.SiacoinOutput{
						Value: types.Siacoins(1),
					})
				},
			},
			{
				fmt.Sprintf("transaction revises file contract %v more than once", giftTxn.FileContractID(0)),
				func(b *types.Block) {
					txn := &b.Transactions[0]
					newRevision := txn.FileContractRevisions[0]
					newRevision.RevisionNumber++
					txn.FileContractRevisions = append(txn.FileContractRevisions, newRevision)
				},
			},
			{
				"file contract revision 0 does not have a higher revision number than its parent",
				func(b *types.Block) {
					newRevision := b.Transactions[0].FileContractRevisions[0]
					newRevision.RevisionNumber = 99

					b.Transactions = append(b.Transactions[:1], types.Transaction{
						FileContractRevisions: []types.FileContractRevision{newRevision},
					})

					// set the initial revision number to be higher than the new
					// revision
					b.Transactions[0].FileContractRevisions[0].RevisionNumber = 100
				},
			},
			{
				"file contract revision 0 does not have a higher revision number than its parent",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					newRevision := txn.FileContractRevisions[0]

					b.Transactions = append(b.Transactions[:1], types.Transaction{
						FileContractRevisions: []types.FileContractRevision{newRevision},
					})
				},
			},
			{
				"transaction contains both a storage proof and other outputs",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.StorageProofs = append(txn.StorageProofs, types.StorageProof{})
				},
			},
		}
		for _, test := range tests {
			corruptBlock := deepCopyBlock(validBlock)
			test.corrupt(&corruptBlock)
			for i := range corruptBlock.Transactions {
				signTxn(&corruptBlock.Transactions[i])
			}
			findBlockNonce(cs, &corruptBlock)

			if err := ValidateBlock(cs, corruptBlock, db.supplementTipBlock(corruptBlock)); err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		}
	}

	// signature test
	{
		tests := []struct {
			desc    string
			corrupt func(*types.Block)
		}{
			{
				"siacoin input with missing signature",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.Signatures = []types.TransactionSignature{txn.Signatures[1]}
				},
			},
			{
				"siafund input with missing signature",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.Signatures = []types.TransactionSignature{txn.Signatures[0]}
				},
			},
			{
				"signature that refers to parent not in transaction",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.Signatures[0].ParentID[0] ^= 255
				},
			},
			{
				"signature that refers to nonexistent public key",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.Signatures[0].PublicKeyIndex = math.MaxUint64
				},
			},
			{
				"redundant signature",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.Signatures = append(txn.Signatures, txn.Signatures[0])
				},
			},
			{
				"timelock of signature 0 has not expired",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.Signatures[0].Timelock = txn.Signatures[0].Timelock + 100
				},
			},
			{
				"invalid partial signature",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.Signatures[0].CoveredFields.WholeTransaction = false
				},
			},
			{
				"invalid partial signature",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.Signatures[0].CoveredFields.WholeTransaction = false
					txn.Signatures[0].CoveredFields.SiacoinInputs = []uint64{0}
					txn.Signatures[0].CoveredFields.SiacoinOutputs = []uint64{0}
					txn.Signatures[0].CoveredFields.SiafundInputs = []uint64{0}
					txn.Signatures[0].CoveredFields.SiafundOutputs = []uint64{0}
					txn.Signatures[0].CoveredFields.FileContracts = []uint64{0}
					txn.Signatures[0].CoveredFields.FileContractRevisions = []uint64{0}
				},
			},
		}
		for _, test := range tests {
			corruptBlock := deepCopyBlock(validBlock)
			for i := range corruptBlock.Transactions {
				signTxn(&corruptBlock.Transactions[i])
			}
			test.corrupt(&corruptBlock)
			findBlockNonce(cs, &corruptBlock)

			if err := ValidateBlock(cs, corruptBlock, db.supplementTipBlock(corruptBlock)); err == nil {
				t.Fatalf("accepted block with %v", test.desc)
			}
		}
	}
}

func updateProofs(au ApplyUpdate, sces []types.SiacoinElement, sfes []types.SiafundElement, fces []types.V2FileContractElement, cies []types.ChainIndexElement) {
	for i := range sces {
		au.UpdateElementProof(&sces[i].StateElement)
	}
	for i := range sfes {
		au.UpdateElementProof(&sfes[i].StateElement)
	}
	for i := range fces {
		au.UpdateElementProof(&fces[i].StateElement)
	}
	for i := range cies {
		au.UpdateElementProof(&cies[i].StateElement)
	}
}

func TestValidateV2Block(t *testing.T) {
	n, genesisBlock := testnet()

	n.HardforkOak.Height = 0
	n.HardforkTax.Height = 0
	n.HardforkFoundation.Height = 0
	n.InitialTarget = types.BlockID{0xFF}
	n.HardforkV2.AllowHeight = 0
	n.HardforkV2.RequireHeight = 0

	giftPrivateKey := types.GeneratePrivateKey()
	giftPublicKey := giftPrivateKey.PublicKey()
	giftPolicy := types.PolicyPublicKey(giftPublicKey)
	giftAddress := types.StandardAddress(giftPublicKey)

	renterPrivateKey := types.GeneratePrivateKey()
	renterPublicKey := renterPrivateKey.PublicKey()
	hostPrivateKey := types.GeneratePrivateKey()
	hostPublicKey := hostPrivateKey.PublicKey()

	signTxn := func(cs State, txn *types.V2Transaction) {
		for i := range txn.SiacoinInputs {
			txn.SiacoinInputs[i].SatisfiedPolicy.Signatures = []types.Signature{giftPrivateKey.SignHash(cs.InputSigHash(*txn))}
		}
		for i := range txn.SiafundInputs {
			txn.SiafundInputs[i].SatisfiedPolicy.Signatures = []types.Signature{giftPrivateKey.SignHash(cs.InputSigHash(*txn))}
		}
		for i := range txn.FileContracts {
			txn.FileContracts[i].RenterSignature = renterPrivateKey.SignHash(cs.ContractSigHash(txn.FileContracts[i]))
			txn.FileContracts[i].HostSignature = hostPrivateKey.SignHash(cs.ContractSigHash(txn.FileContracts[i]))
		}
		for i := range txn.FileContractRevisions {
			txn.FileContractRevisions[i].Revision.RenterSignature = renterPrivateKey.SignHash(cs.ContractSigHash(txn.FileContractRevisions[i].Revision))
			txn.FileContractRevisions[i].Revision.HostSignature = hostPrivateKey.SignHash(cs.ContractSigHash(txn.FileContractRevisions[i].Revision))
		}
		for i := range txn.FileContractResolutions {
			r, ok := txn.FileContractResolutions[i].Resolution.(*types.V2FileContractRenewal)
			if !ok {
				continue
			}
			r.RenterSignature = renterPrivateKey.SignHash(cs.RenewalSigHash(*r))
			r.HostSignature = hostPrivateKey.SignHash(cs.RenewalSigHash(*r))
		}
	}

	giftAmountSC := types.Siacoins(100)
	giftAmountSF := uint64(100)
	v1GiftFC := prepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), 100, 100, types.VoidAddress)
	v1GiftFC.Filesize = 65
	v1GiftFC.FileMerkleRoot = blake2b.SumPair((State{}).StorageProofLeafHash([]byte{1}), (State{}).StorageProofLeafHash([]byte{2}))
	v2GiftFC := types.V2FileContract{
		Capacity:         v1GiftFC.Filesize,
		Filesize:         v1GiftFC.Filesize,
		FileMerkleRoot:   v1GiftFC.FileMerkleRoot,
		ProofHeight:      20,
		ExpirationHeight: 30,
		RenterOutput:     v1GiftFC.ValidProofOutputs[0],
		HostOutput:       v1GiftFC.ValidProofOutputs[1],
		MissedHostValue:  v1GiftFC.MissedProofOutputs[1].Value,
		TotalCollateral:  v1GiftFC.Payout,
		RenterPublicKey:  renterPublicKey,
		HostPublicKey:    hostPublicKey,
	}
	contractCost := v2GiftFC.RenterOutput.Value.Add(v2GiftFC.HostOutput.Value).Add(n.GenesisState().V2FileContractTax(v2GiftFC))

	giftTxn := types.V2Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: giftAddress, Value: giftAmountSC},
			{Address: giftAddress, Value: contractCost},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Address: giftAddress, Value: giftAmountSF},
		},
		FileContracts: []types.V2FileContract{v2GiftFC},
	}

	genesisBlock.Transactions = nil
	genesisBlock.V2 = &types.V2BlockData{
		Transactions: []types.V2Transaction{giftTxn},
	}

	cs, au := ApplyBlock(n.GenesisState(), genesisBlock, V1BlockSupplement{}, time.Time{})
	checkApplyUpdate(t, cs, au)
	sces := make([]types.SiacoinElement, len(au.SiacoinElementDiffs()))
	for i := range sces {
		sces[i] = au.SiacoinElementDiffs()[i].SiacoinElement.Copy()
	}
	sfes := make([]types.SiafundElement, len(au.SiafundElementDiffs()))
	for i := range sfes {
		sfes[i] = au.SiafundElementDiffs()[i].SiafundElement.Copy()
	}
	fces := make([]types.V2FileContractElement, len(au.V2FileContractElementDiffs()))
	for i := range fces {
		fces[i] = au.V2FileContractElementDiffs()[i].V2FileContractElement.Copy()
	}
	cies := []types.ChainIndexElement{au.ChainIndexElement()}

	db, cs := newConsensusDB(n, genesisBlock)

	fc := v2GiftFC
	fc.TotalCollateral = fc.HostOutput.Value

	rev1 := v2GiftFC
	rev1.RevisionNumber++
	minerFee := types.Siacoins(1)
	b := types.Block{
		ParentID:  genesisBlock.ID(),
		Timestamp: types.CurrentTimestamp(),
		V2: &types.V2BlockData{
			Height: 1,
			Transactions: []types.V2Transaction{{
				SiacoinInputs: []types.V2SiacoinInput{{
					Parent:          sces[0].Copy(),
					SatisfiedPolicy: types.SatisfiedPolicy{Policy: giftPolicy},
				}},
				SiafundInputs: []types.V2SiafundInput{{
					Parent:          sfes[0].Copy(),
					ClaimAddress:    types.VoidAddress,
					SatisfiedPolicy: types.SatisfiedPolicy{Policy: giftPolicy},
				}},
				SiacoinOutputs: []types.SiacoinOutput{
					{Value: giftAmountSC.Sub(minerFee).Sub(contractCost), Address: giftAddress},
				},
				SiafundOutputs: []types.SiafundOutput{
					{Value: giftAmountSF / 2, Address: giftAddress},
					{Value: giftAmountSF / 2, Address: types.VoidAddress},
				},
				FileContracts: []types.V2FileContract{fc},
				FileContractRevisions: []types.V2FileContractRevision{
					{Parent: au.V2FileContractElementDiffs()[0].V2FileContractElement.Copy(), Revision: rev1},
				},
				MinerFee: minerFee,
			}},
		},
		MinerPayouts: []types.SiacoinOutput{{
			Address: types.VoidAddress,
			Value:   cs.BlockReward().Add(minerFee),
		}},
	}
	signTxn(cs, &b.V2.Transactions[0])
	b.V2.Commitment = cs.Commitment(b.MinerPayouts[0].Address, b.Transactions, b.V2Transactions())
	findBlockNonce(cs, &b)

	// initial block should be valid
	validBlock := deepCopyBlock(b)
	if err := ValidateBlock(cs, validBlock, db.supplementTipBlock(validBlock)); err != nil {
		t.Fatal(err)
	}

	{
		tests := []struct {
			errString string
			corrupt   func(*types.Block)
		}{
			{
				"block supplement is invalid: v1 block supplements are not allowed after v2 hardfork is complete",
				func(b *types.Block) {
					b.Transactions = []types.Transaction{{}}
				},
			},
			{
				"block height does not increment parent height",
				func(b *types.Block) {
					b.V2.Height = 0
				},
			},
			{
				"block exceeds maximum weight",
				func(b *types.Block) {
					data := make([]byte, cs.MaxBlockWeight())
					b.V2.Transactions = append(b.V2.Transactions, types.V2Transaction{
						ArbitraryData: data,
					})
				},
			},
			{
				"transactions cannot be empty",
				func(b *types.Block) {
					b.V2.Transactions = append(b.V2.Transactions, types.V2Transaction{})
				},
			},
			{
				"wrong parent ID",
				func(b *types.Block) {
					b.ParentID[0] ^= 255
				},
			},
			{
				"block has timestamp too far in the past",
				func(b *types.Block) {
					b.Timestamp = cs.PrevTimestamps[0].AddDate(-1, 0, 0)
				},
			},
			{
				"must have exactly one miner payout",
				func(b *types.Block) {
					b.MinerPayouts = nil
				},
			},
			{
				"must have exactly one miner payout",
				func(b *types.Block) {
					b.MinerPayouts = []types.SiacoinOutput{
						{
							Address: types.VoidAddress,
							Value:   cs.BlockReward().Div64(2),
						},
						{
							Address: types.VoidAddress,
							Value:   cs.BlockReward().Div64(2),
						}}
				},
			},
			{
				"miner payout has zero value",
				func(b *types.Block) {
					b.MinerPayouts = []types.SiacoinOutput{{
						Address: types.VoidAddress,
						Value:   types.ZeroCurrency,
					}}
				},
			},
			{
				"miner payout sum (150 KS) does not match block reward + fees (300.001 KS)",
				func(b *types.Block) {
					b.MinerPayouts = []types.SiacoinOutput{{
						Address: types.VoidAddress,
						Value:   cs.BlockReward().Div64(2),
					}}
				},
			},
			{
				"siacoin output 0 has zero value",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					for i := range txn.SiacoinOutputs {
						txn.SiacoinOutputs[i].Value = types.ZeroCurrency
					}
					txn.SiacoinInputs = nil
					txn.FileContracts = nil
				},
			},
			{
				"siafund output 0 has zero value",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					for i := range txn.SiafundOutputs {
						txn.SiafundOutputs[i].Value = 0
					}
					txn.SiafundInputs = nil
				},
			},
			{
				"miner payout sum (300.001 KS) does not match block reward + fees (300 KS)",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.MinerFee = types.ZeroCurrency
				},
			},
			{
				"v2 transaction fees overflow",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.MinerFee = types.MaxCurrency
				},
			},
			{
				"siacoin inputs (100 SC) do not equal outputs",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Add(types.NewCurrency64(1))
				},
			},
			{
				"siacoin inputs (100 SC) do not equal outputs",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Sub(types.NewCurrency64(1))
				},
			},
			{
				"siafund inputs (100 SF) do not equal outputs",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiafundOutputs[0].Value++
				},
			},
			{
				"siafund inputs (100 SF) do not equal outputs",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiafundOutputs[0].Value--
				},
			},
			{
				"transaction outputs exceed inputs",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinOutputs = []types.SiacoinOutput{
						{Address: types.VoidAddress, Value: types.MaxCurrency},
						{Address: types.VoidAddress, Value: types.MaxCurrency},
					}
				},
			},
			{
				"transaction outputs exceed inputs",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiafundOutputs = []types.SiafundOutput{
						{Address: types.VoidAddress, Value: 10001},
					}
				},
			},
			{
				"siacoin input 1 double-spends parent output",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinInputs = append(txn.SiacoinInputs, txn.SiacoinInputs[0])
				},
			},
			{
				"siafund input 1 double-spends parent output",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiafundInputs = append(txn.SiafundInputs, txn.SiafundInputs[0])
				},
			},
			{
				"siacoin input 0 claims incorrect policy",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinInputs[0].SatisfiedPolicy.Policy = types.AnyoneCanSpend()
				},
			},
			{
				"siafund input 0 claims incorrect policy",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiafundInputs[0].SatisfiedPolicy.Policy = types.AnyoneCanSpend()
				},
			},
			{
				"transaction changes Foundation address, but does not spend an input controlled by current address",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					addr := types.VoidAddress
					txn.NewFoundationAddress = &addr
				},
			},
			{
				"file contract revision 0 has proof height (0) that has already passed",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContractRevisions[0].Revision.ProofHeight = cs.Index.Height
				},
			},
			{
				"file contract revision 0 leaves no time between proof height (20) and expiration height (20)",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContractRevisions[0].Revision.ExpirationHeight = txn.FileContractRevisions[0].Revision.ProofHeight
				},
			},
			{
				"file contract revision 0 does not increase revision number (0 -> 0)",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContractRevisions[0].Revision.RevisionNumber = 0
				},
			},
			{
				"file contract revision 0 does not increase revision number (100 -> 99)",
				func(b *types.Block) {
					// create a revision
					b.V2.Transactions[0].FileContractRevisions[0].Revision.RevisionNumber = 100
					signTxn(cs, &b.V2.Transactions[0])

					// create a second revision with a lower revision number
					newRevision := b.V2.Transactions[0].FileContractRevisions[0]
					newRevision.Revision.RevisionNumber = 99
					txn := types.V2Transaction{
						FileContractRevisions: []types.V2FileContractRevision{newRevision},
					}
					// sign and add the transaction to the block
					signTxn(cs, &txn)
					b.V2.Transactions = append(b.V2.Transactions, txn)
				},
			},
			{
				"file contract revision 0 modifies output sum (2 SC -> 3 SC)",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContractRevisions[0].Revision.HostOutput.Value = txn.FileContractRevisions[0].Revision.HostOutput.Value.Add(types.Siacoins(1))
				},
			},
			{
				fmt.Sprintf("file contract revision 1 parent (%v) has already been revised", au.V2FileContractElementDiffs()[0].V2FileContractElement.ID),
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					newRevision := txn.FileContractRevisions[0]
					newRevision.Revision.RevisionNumber++
					txn.FileContractRevisions = append(txn.FileContractRevisions, newRevision)
				},
			},
			{
				"file contract 0 has proof height (0) that has already passed",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContracts[0].ProofHeight = 0
				},
			},
			{
				"file contract 0 leaves no time between proof height (30) and expiration height (30)",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContracts[0].ProofHeight = txn.FileContracts[0].ExpirationHeight
				},
			},
			{
				"siacoin inputs (100 SC) do not equal outputs (101.04 SC)",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContracts[0].HostOutput.Value = txn.FileContracts[0].HostOutput.Value.Add(types.Siacoins(1))
				},
			},
			{
				"siacoin inputs (100 SC) do not equal outputs (101 SC)",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Add(types.Siacoins(1))
					txn.FileContracts[0].TotalCollateral = txn.FileContracts[0].TotalCollateral.Sub(types.Siacoins(1))
				},
			},
			{
				"file contract 0 has missed host value (2 SC) exceeding valid host value (1 SC)",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContracts[0].MissedHostValue = txn.FileContracts[0].HostOutput.Value.Add(types.Siacoins(1))
				},
			},
			{
				"file contract 0 has total collateral (2 SC) exceeding valid host value (1 SC)",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContracts[0].TotalCollateral = txn.FileContracts[0].HostOutput.Value.Add(types.Siacoins(1))
				},
			},
			{
				fmt.Sprintf("siacoin input 0 spends output (%v) not present in the accumulator", sces[0].ID),
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinInputs[0].Parent.StateElement.LeafIndex ^= 1
				},
			},
			{
				fmt.Sprintf("siafund input 0 spends output (%v) not present in the accumulator", sfes[0].ID),
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiafundInputs[0].Parent.StateElement.LeafIndex ^= 1
				},
			},
			{
				"siacoin input 0 failed to satisfy spend policy: superfluous preimage(s)",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinInputs[0].SatisfiedPolicy.Preimages = [][32]byte{{1}}
				},
			},
			{
				"siafund input 0 failed to satisfy spend policy: superfluous preimage(s)",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiafundInputs[0].SatisfiedPolicy.Preimages = [][32]byte{{1}}
				},
			},
			{
				fmt.Sprintf("file contract renewal 0 parent (%v) has already been revised by contract revision", fces[0].ID),
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContractResolutions = append(txn.FileContractResolutions, types.V2FileContractResolution{
						Parent:     fces[0].Copy(),
						Resolution: &types.V2FileContractExpiration{},
					})
				},
			},
			{
				"attestation 0 has empty key",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.Attestations = append(txn.Attestations, types.Attestation{})
				},
			},
			{
				"attestation 0 has invalid signature",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.Attestations = append(txn.Attestations, types.Attestation{
						Key:       "HostAnnouncement",
						PublicKey: giftPublicKey,
					})
				},
			},
		}
		for _, test := range tests {
			corruptBlock := deepCopyBlock(validBlock)
			test.corrupt(&corruptBlock)
			signTxn(cs, &corruptBlock.V2.Transactions[0])
			if len(corruptBlock.MinerPayouts) > 0 {
				corruptBlock.V2.Commitment = cs.Commitment(corruptBlock.MinerPayouts[0].Address, corruptBlock.Transactions, corruptBlock.V2Transactions())
			}
			findBlockNonce(cs, &corruptBlock)

			if err := ValidateBlock(cs, corruptBlock, db.supplementTipBlock(corruptBlock)); err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		}
	}

	cs, testAU := ApplyBlock(cs, validBlock, db.supplementTipBlock(validBlock), time.Now())
	checkApplyUpdate(t, cs, testAU)
	db.applyBlock(testAU)
	updateProofs(testAU, sces, sfes, fces, cies)

	testSces := make([]types.SiacoinElement, len(testAU.SiacoinElementDiffs()))
	for i := range testSces {
		testSces[i] = testAU.SiacoinElementDiffs()[i].SiacoinElement.Copy()
	}
	testSfes := make([]types.SiafundElement, len(testAU.SiafundElementDiffs()))
	for i := range testSfes {
		testSfes[i] = testAU.SiafundElementDiffs()[i].SiafundElement.Copy()
	}
	testFces := make([]types.V2FileContractElement, len(testAU.V2FileContractElementDiffs()))
	for i := range testFces {
		testFces[i] = testAU.V2FileContractElementDiffs()[i].V2FileContractElement.Copy()
	}
	cies = append(cies, testAU.ChainIndexElement())

	// mine empty blocks
	blockID := validBlock.ID()
	for i := uint64(0); i < v2GiftFC.ProofHeight; i++ {
		b := types.Block{
			ParentID:  blockID,
			Timestamp: types.CurrentTimestamp(),
			V2: &types.V2BlockData{
				Height: cs.Index.Height + 1,
			},
			MinerPayouts: []types.SiacoinOutput{{
				Address: types.VoidAddress,
				Value:   cs.BlockReward(),
			}},
		}
		b.V2.Commitment = cs.Commitment(b.MinerPayouts[0].Address, b.Transactions, b.V2Transactions())

		findBlockNonce(cs, &b)
		if err := ValidateBlock(cs, b, db.supplementTipBlock(b)); err != nil {
			t.Fatal(err)
		}
		cs, au = ApplyBlock(cs, b, db.supplementTipBlock(validBlock), time.Now())
		checkApplyUpdate(t, cs, au)
		db.applyBlock(au)
		updateProofs(au, sces, sfes, fces, cies)
		updateProofs(au, testSces, testSfes, testFces, nil)
		cies = append(cies, au.ChainIndexElement())

		blockID = b.ID()
	}

	b = types.Block{
		ParentID:  blockID,
		Timestamp: types.CurrentTimestamp(),
		V2: &types.V2BlockData{
			Height: cs.Index.Height + 1,
			Transactions: []types.V2Transaction{
				{
					FileContractResolutions: []types.V2FileContractResolution{{
						Parent: testFces[0].Copy(),
						Resolution: &types.V2StorageProof{
							ProofIndex: cies[len(cies)-2].Copy(),
							Leaf:       [64]byte{1},
							Proof:      []types.Hash256{cs.StorageProofLeafHash([]byte{2})},
						},
					}},
				},
			},
		},
		MinerPayouts: []types.SiacoinOutput{{
			Address: types.VoidAddress,
			Value:   cs.BlockReward(),
		}},
	}
	if cs.StorageProofLeafIndex(testFces[0].V2FileContract.Filesize, cies[len(cies)-2].ChainIndex.ID, types.FileContractID(testFces[0].ID)) == 1 {
		b.V2.Transactions[0].FileContractResolutions[0].Resolution = &types.V2StorageProof{
			ProofIndex: cies[len(cies)-2].Copy(),
			Leaf:       [64]byte{2},
			Proof:      []types.Hash256{cs.StorageProofLeafHash([]byte{1})},
		}
	}

	signTxn(cs, &b.V2.Transactions[0])
	b.V2.Commitment = cs.Commitment(b.MinerPayouts[0].Address, b.Transactions, b.V2Transactions())
	findBlockNonce(cs, &validBlock)

	// initial block should be valid
	validBlock = deepCopyBlock(b)
	if err := ValidateBlock(cs, validBlock, db.supplementTipBlock(validBlock)); err != nil {
		t.Fatal(err)
	}

	{
		tests := []struct {
			desc    string
			corrupt func(*types.Block)
		}{
			{
				"double spend of non-parent siacoin output",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinInputs = append(txn.SiacoinInputs, types.V2SiacoinInput{
						Parent:          testSces[0].Copy(),
						SatisfiedPolicy: types.SatisfiedPolicy{Policy: giftPolicy},
					})
				},
			},
			{
				"double spend of non-parent siafund output",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiafundInputs = append(txn.SiafundInputs, types.V2SiafundInput{
						Parent:          testSfes[0].Copy(),
						SatisfiedPolicy: types.SatisfiedPolicy{Policy: giftPolicy},
					})
				},
			},
			{
				"revision after proof height",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					rev := testFces[0].V2FileContract
					rev.RevisionNumber++
					txn.FileContractRevisions = []types.V2FileContractRevision{{
						Parent:   testFces[0].Copy(),
						Revision: rev,
					}}
				},
			},
			{
				"storage proof expiration at wrong proof height",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContractResolutions = []types.V2FileContractResolution{{
						Parent: testFces[0].Copy(),
						Resolution: &types.V2StorageProof{
							ProofIndex: cies[len(cies)-1].Copy(),
						},
					}}
				},
			},
			{
				"file contract expiration submitted before expiration height",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContractResolutions = []types.V2FileContractResolution{{
						Parent:     testFces[0].Copy(),
						Resolution: &types.V2FileContractExpiration{},
					}}
				},
			},
			{
				"file contract renewal with invalid final revision",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinInputs = []types.V2SiacoinInput{{
						Parent:          sces[1].Copy(),
						SatisfiedPolicy: types.SatisfiedPolicy{Policy: giftPolicy},
					}}

					resolution := types.V2FileContractRenewal{
						FinalRenterOutput: types.SiacoinOutput{Value: types.Siacoins(1e6)},
						NewContract:       testFces[0].V2FileContract,
					}
					txn.FileContractResolutions = []types.V2FileContractResolution{{
						Parent:     testFces[0].Copy(),
						Resolution: &resolution,
					}}
				},
			},
			{
				"file contract renewal with invalid initial revision",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinInputs = []types.V2SiacoinInput{{
						Parent:          sces[1].Copy(),
						SatisfiedPolicy: types.SatisfiedPolicy{Policy: giftPolicy},
					}}

					rev := testFces[0].V2FileContract
					rev.ExpirationHeight = rev.ProofHeight
					resolution := types.V2FileContractRenewal{
						FinalRenterOutput: rev.RenterOutput,
						FinalHostOutput:   rev.HostOutput,
						NewContract:       rev,
					}
					txn.FileContractResolutions = []types.V2FileContractResolution{{
						Parent:     testFces[0].Copy(),
						Resolution: &resolution,
					}}
				},
			},
		}
		for _, test := range tests {
			corruptBlock := deepCopyBlock(validBlock)
			test.corrupt(&corruptBlock)
			signTxn(cs, &corruptBlock.V2.Transactions[0])
			if len(corruptBlock.MinerPayouts) > 0 {
				corruptBlock.V2.Commitment = cs.Commitment(corruptBlock.MinerPayouts[0].Address, corruptBlock.Transactions, corruptBlock.V2Transactions())
			}
			findBlockNonce(cs, &corruptBlock)

			if err := ValidateBlock(cs, corruptBlock, db.supplementTipBlock(corruptBlock)); err == nil {
				t.Fatalf("accepted block with %v", test.desc)
			}
		}
	}
}

func TestV2ImmatureSiacoinOutput(t *testing.T) {
	n, genesisBlock := testnet()
	n.HardforkV2.AllowHeight = 1

	db, cs := newConsensusDB(n, genesisBlock)

	pk := types.NewPrivateKeyFromSeed(frand.Bytes(32))
	sp := types.PolicyPublicKey(pk.PublicKey())
	addr := sp.Address()

	utxos := make(map[types.SiacoinOutputID]types.SiacoinElement)
	mineBlock := func(minerAddr types.Address, v2Txns []types.V2Transaction) error {
		t.Helper()
		b := types.Block{
			ParentID:  cs.Index.ID,
			Timestamp: time.Now(),
			MinerPayouts: []types.SiacoinOutput{
				{Address: minerAddr, Value: cs.BlockReward()},
			},
		}
		if cs.Index.Height >= n.HardforkV2.AllowHeight {
			b.V2 = &types.V2BlockData{
				Height:       cs.Index.Height + 1,
				Transactions: v2Txns,
			}
			b.V2.Commitment = cs.Commitment(minerAddr, b.Transactions, b.V2Transactions())
		}

		findBlockNonce(cs, &b)
		if err := ValidateBlock(cs, b, db.supplementTipBlock(b)); err != nil {
			return err
		}

		var cau ApplyUpdate
		cs, cau = ApplyBlock(cs, b, db.supplementTipBlock(b), db.ancestorTimestamp(b.ParentID))
		checkApplyUpdate(t, cs, cau)
		for _, sce := range cau.SiacoinElementDiffs() {
			if sce.Spent {
				delete(utxos, sce.SiacoinElement.ID)
			} else if sce.SiacoinElement.SiacoinOutput.Address == addr {
				utxos[sce.SiacoinElement.ID] = sce.SiacoinElement.Copy()
			}
		}

		for id, sce := range utxos {
			cau.UpdateElementProof(&sce.StateElement)
			utxos[id] = sce.Move()
		}

		db.applyBlock(cau)
		return nil
	}

	if err := mineBlock(addr, nil); err != nil {
		t.Fatal(err)
	} else if cs.Index.Height != 1 {
		t.Fatalf("expected height %v, got %v", 1, cs.Index.Height)
	} else if len(utxos) != 1 {
		t.Fatalf("expected %v utxos, got %v", 1, len(utxos))
	}

	// grab the one element
	var sce types.SiacoinElement
	for _, sce = range utxos {
		break
	}

	// construct a transaction using the immature miner payout utxo
	txn := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{
			{Parent: sce.Copy()},
		},
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: types.VoidAddress, Value: sce.SiacoinOutput.Value},
		},
	}
	sigHash := cs.InputSigHash(txn)
	txn.SiacoinInputs[0].SatisfiedPolicy = types.SatisfiedPolicy{
		Policy:     sp,
		Signatures: []types.Signature{pk.SignHash(sigHash)},
	}

	// check for immature payout error
	if err := mineBlock(types.VoidAddress, []types.V2Transaction{txn}); err == nil {
		t.Fatal("expected immature output error, got nil")
	} else if !strings.Contains(err.Error(), "has immature parent") {
		t.Fatalf("expected immature output err, got %v", err)
	}
}

func TestEarlyV2Transaction(t *testing.T) {
	n := &Network{InitialTarget: types.BlockID{0xFF}}
	n.HardforkV2.AllowHeight = 1
	exp := errors.New("v2 transactions are not allowed until v2 hardfork begins")
	if err := ValidateV2Transaction(NewMidState(n.GenesisState()), types.V2Transaction{}); err == nil || err.Error() != exp.Error() {
		t.Fatalf("expected %q, got %q", exp, err)
	}
}

func TestWindowRevision(t *testing.T) {
	n, genesisBlock := testnet()
	n.InitialTarget = types.BlockID{0xFF}

	// create file contract with window that is already open
	sk := types.NewPrivateKeyFromSeed(make([]byte, 32))
	uc := types.StandardUnlockConditions(sk.PublicKey())
	fc := types.FileContract{
		WindowStart: 0,
		WindowEnd:   3,
		UnlockHash:  uc.UnlockHash(),
	}
	genesisBlock.Transactions = []types.Transaction{{
		FileContracts: []types.FileContract{fc},
	}}
	db, cs := newConsensusDB(n, genesisBlock)

	// attempt to extend the window
	rev := fc
	rev.WindowStart = 1
	rev.RevisionNumber++
	txn := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         genesisBlock.Transactions[0].FileContractID(0),
			UnlockConditions: uc,
			FileContract:     rev,
		}},
		Signatures: []types.TransactionSignature{{
			ParentID:       types.Hash256(genesisBlock.Transactions[0].FileContractID(0)),
			PublicKeyIndex: 0,
			Timelock:       0,
			CoveredFields:  types.CoveredFields{WholeTransaction: true},
		}},
	}
	sig := sk.SignHash(cs.WholeSigHash(txn, txn.Signatures[0].ParentID, 0, 0, nil))
	txn.Signatures[0].Signature = sig[:]

	b := types.Block{
		ParentID:  genesisBlock.ID(),
		Timestamp: types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{
			Address: types.VoidAddress,
			Value:   cs.BlockReward(),
		}},
		Transactions: []types.Transaction{txn},
	}

	findBlockNonce(cs, &b)
	if err := ValidateBlock(cs, b, db.supplementTipBlock(b)); err == nil || !strings.Contains(err.Error(), "proof window has opened") {
		t.Fatal("expected error when extending window")
	}
}

func TestV2RevisionApply(t *testing.T) {
	n, genesisBlock := testnet()

	n.HardforkOak.Height = 0
	n.HardforkTax.Height = 0
	n.HardforkFoundation.Height = 0
	n.InitialTarget = types.BlockID{0xFF}
	n.HardforkV2.AllowHeight = 0
	n.HardforkV2.RequireHeight = 0

	pk := types.GeneratePrivateKey()
	addr := types.AnyoneCanSpend().Address()
	fc := types.V2FileContract{
		ProofHeight:      100,
		ExpirationHeight: 150,
		RenterPublicKey:  pk.PublicKey(),
		HostPublicKey:    pk.PublicKey(),
		HostOutput: types.SiacoinOutput{
			Address: addr, Value: types.Siacoins(10),
		},
		RenterOutput: types.SiacoinOutput{
			Address: addr, Value: types.ZeroCurrency,
		},
	}
	cs := n.GenesisState()
	sigHash := cs.ContractSigHash(fc)
	fc.HostSignature = pk.SignHash(sigHash)
	fc.RenterSignature = pk.SignHash(sigHash)
	contractCost := cs.V2FileContractTax(fc).Add(fc.HostOutput.Value)

	genesisTxn := types.V2Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: addr, Value: contractCost},
		},
		FileContracts: []types.V2FileContract{fc},
	}
	genesisBlock.V2 = &types.V2BlockData{
		Transactions: []types.V2Transaction{genesisTxn},
	}
	contractID := genesisTxn.V2FileContractID(genesisTxn.ID(), 0)
	fces := make(map[types.FileContractID]types.V2FileContractElement)
	applyContractChanges := func(au ApplyUpdate) {
		for _, fce := range au.V2FileContractElementDiffs() {
			switch {
			case fce.Resolution != nil:
				delete(fces, fce.V2FileContractElement.ID)
			case fce.Revision != nil:
				fce.V2FileContractElement.V2FileContract = *fce.Revision
				fces[fce.V2FileContractElement.ID] = fce.V2FileContractElement.Copy()
			default:
				fces[fce.V2FileContractElement.ID] = fce.V2FileContractElement.Copy()
			}
		}

		// update proofs
		for key, fce := range fces {
			au.UpdateElementProof(&fce.StateElement)
			fces[key] = fce.Move()
		}
	}

	checkRevision := func(t *testing.T, expected uint64) {
		t.Helper()
		fce, ok := fces[contractID]
		if !ok {
			t.Fatal("missing revision")
		} else if fce.V2FileContract.RevisionNumber != expected {
			t.Fatalf("expected revision %v, got %v", expected, fce.V2FileContract.RevisionNumber)
		}
	}

	cs, au := ApplyBlock(cs, genesisBlock, V1BlockSupplement{}, time.Time{})
	applyContractChanges(au)
	checkRevision(t, 0)

	ms := NewMidState(cs)

	rev1 := fc
	rev1.RevisionNumber = 100
	rev1SigHash := cs.ContractSigHash(rev1)
	rev1.HostSignature = pk.SignHash(rev1SigHash)
	rev1.RenterSignature = pk.SignHash(rev1SigHash)

	txn1 := types.V2Transaction{
		FileContractRevisions: []types.V2FileContractRevision{
			{Parent: fces[contractID].Copy(), Revision: rev1},
		},
	}

	if err := ValidateV2Transaction(ms, txn1); err != nil {
		t.Fatal(err)
	}
	ms.ApplyV2Transaction(txn1)

	rev2 := fc
	rev2.RevisionNumber = 50
	rev2SigHash := cs.ContractSigHash(rev2)
	rev2.HostSignature = pk.SignHash(rev2SigHash)
	rev2.RenterSignature = pk.SignHash(rev2SigHash)

	txn2 := types.V2Transaction{
		FileContractRevisions: []types.V2FileContractRevision{
			{Parent: fces[contractID].Copy(), Revision: rev2},
		},
	}
	if err := ValidateV2Transaction(ms, txn2); err == nil {
		t.Error("expected error when applying revision with lower revision number")
	}
	ms.ApplyV2Transaction(txn2)

	b := types.Block{
		ParentID: genesisBlock.ID(),
		V2: &types.V2BlockData{
			Height:       cs.Index.Height + 1,
			Transactions: []types.V2Transaction{txn1},
		},
	}
	_, au = ApplyBlock(cs, b, V1BlockSupplement{}, time.Time{})
	applyContractChanges(au)
	checkRevision(t, 100)
}

func TestV2RenewalResolution(t *testing.T) {
	n, genesisBlock := testnet()

	n.HardforkOak.Height = 0
	n.HardforkTax.Height = 0
	n.HardforkFoundation.Height = 0
	n.InitialTarget = types.BlockID{0xFF}
	n.HardforkV2.AllowHeight = 0
	n.HardforkV2.RequireHeight = 0

	pk := types.GeneratePrivateKey()
	addr := types.AnyoneCanSpend().Address()
	fc := types.V2FileContract{
		ProofHeight:      100,
		ExpirationHeight: 150,
		RenterPublicKey:  pk.PublicKey(),
		HostPublicKey:    pk.PublicKey(),
		HostOutput: types.SiacoinOutput{
			Address: addr, Value: types.Siacoins(10),
		},
		RenterOutput: types.SiacoinOutput{
			Address: addr, Value: types.Siacoins(10),
		},
		MissedHostValue: types.Siacoins(10),
	}
	cs := n.GenesisState()
	sigHash := cs.ContractSigHash(fc)
	fc.HostSignature = pk.SignHash(sigHash)
	fc.RenterSignature = pk.SignHash(sigHash)

	genesisTxn := types.V2Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: addr, Value: types.Siacoins(1000)},
		},
		FileContracts: []types.V2FileContract{fc},
	}
	genesisBlock.V2 = &types.V2BlockData{
		Transactions: []types.V2Transaction{genesisTxn},
	}
	contractID := genesisTxn.V2FileContractID(genesisTxn.ID(), 0)
	fces := make(map[types.FileContractID]types.V2FileContractElement)
	genesisOutput := genesisTxn.EphemeralSiacoinOutput(0)
	applyChanges := func(au ApplyUpdate) {
		for _, fce := range au.V2FileContractElementDiffs() {
			switch {
			case fce.Resolution != nil:
				delete(fces, fce.V2FileContractElement.ID)
			case fce.Revision != nil:
				fce.V2FileContractElement.V2FileContract = *fce.Revision
				fces[fce.V2FileContractElement.ID] = fce.V2FileContractElement.Copy()
			default:
				fces[fce.V2FileContractElement.ID] = fce.V2FileContractElement.Copy()
			}
		}
		for _, sce := range au.SiacoinElementDiffs() {
			if sce.SiacoinElement.ID == genesisOutput.ID {
				genesisOutput = sce.SiacoinElement.Copy()
				break
			}
		}

		// update proofs
		au.UpdateElementProof(&genesisOutput.StateElement)
		for key, fce := range fces {
			au.UpdateElementProof(&fce.StateElement)
			fces[key] = fce.Move()
		}
	}

	// confirm the contract
	cs, au := ApplyBlock(cs, genesisBlock, V1BlockSupplement{}, time.Time{})
	applyChanges(au)

	tests := []struct {
		desc      string
		renewFn   func(*types.V2Transaction)
		errString string
	}{
		{
			desc:    "valid renewal",
			renewFn: func(vt *types.V2Transaction) {}, // no changes should be a valid renewal
		},
		{
			desc: "valid renewal - no renter rollover",
			renewFn: func(txn *types.V2Transaction) {
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				renewal.FinalRenterOutput.Value = renewal.RenterRollover
				renewal.RenterRollover = types.ZeroCurrency
				// subtract the renter cost from the change output
				txn.SiacoinOutputs[0].Value = txn.SiacoinInputs[0].Parent.SiacoinOutput.Value.Sub(renewal.NewContract.RenterOutput.Value).Sub(cs.V2FileContractTax(renewal.NewContract))
			},
		},
		{
			desc: "valid renewal - no host rollover",
			renewFn: func(txn *types.V2Transaction) {
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				renewal.FinalHostOutput.Value = renewal.HostRollover
				renewal.HostRollover = types.ZeroCurrency
				// subtract the host cost from the change output
				txn.SiacoinOutputs[0].Value = txn.SiacoinInputs[0].Parent.SiacoinOutput.Value.Sub(renewal.NewContract.HostOutput.Value).Sub(cs.V2FileContractTax(renewal.NewContract))
			},
		},
		{
			desc: "valid renewal - partial host rollover",
			renewFn: func(txn *types.V2Transaction) {
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				partial := renewal.NewContract.MissedHostValue.Div64(2)
				renewal.FinalHostOutput.Value = partial
				renewal.HostRollover = renewal.HostRollover.Sub(partial)
				// subtract the host cost from the change output
				txn.SiacoinOutputs[0].Value = txn.SiacoinInputs[0].Parent.SiacoinOutput.Value.Sub(partial).Sub(cs.V2FileContractTax(renewal.NewContract))
			},
		},
		{
			desc: "valid renewal - partial renter rollover",
			renewFn: func(txn *types.V2Transaction) {
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				partial := renewal.NewContract.RenterOutput.Value.Div64(2)
				renewal.FinalRenterOutput.Value = partial
				renewal.RenterRollover = renewal.RenterRollover.Sub(partial)
				// subtract the host cost from the change output
				txn.SiacoinOutputs[0].Value = txn.SiacoinInputs[0].Parent.SiacoinOutput.Value.Sub(partial).Sub(cs.V2FileContractTax(renewal.NewContract))
			},
		},
		{
			desc: "valid renewal - changed host payout",
			renewFn: func(txn *types.V2Transaction) {
				// transfers part of the renter payout to the host
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				renewal.FinalHostOutput.Value = renewal.HostRollover
				renewal.HostRollover = types.ZeroCurrency
				renewal.FinalRenterOutput.Value = renewal.RenterRollover
				renewal.RenterRollover = types.ZeroCurrency
				partial := renewal.FinalRenterOutput.Value.Div64(2)
				renewal.FinalRenterOutput.Value = partial
				renewal.FinalHostOutput.Value = renewal.FinalHostOutput.Value.Add(partial)
				// subtract the cost from the change output
				txn.SiacoinOutputs[0].Value = txn.SiacoinInputs[0].Parent.SiacoinOutput.Value.Sub(renewal.NewContract.RenterOutput.Value).Sub(renewal.NewContract.HostOutput.Value).Sub(cs.V2FileContractTax(renewal.NewContract))
			},
		},
		{
			desc: "valid renewal - changed renter payout",
			renewFn: func(txn *types.V2Transaction) {
				// transfers part of the host payout to the renter
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				renewal.FinalHostOutput.Value = renewal.HostRollover
				renewal.HostRollover = types.ZeroCurrency
				renewal.FinalRenterOutput.Value = renewal.RenterRollover
				renewal.RenterRollover = types.ZeroCurrency
				partial := renewal.FinalHostOutput.Value.Div64(2)
				renewal.FinalRenterOutput.Value = partial
				renewal.FinalRenterOutput.Value = renewal.FinalRenterOutput.Value.Add(partial)
				// subtract the cost from the change output
				txn.SiacoinOutputs[0].Value = txn.SiacoinInputs[0].Parent.SiacoinOutput.Value.Sub(renewal.NewContract.RenterOutput.Value).Sub(renewal.NewContract.HostOutput.Value).Sub(cs.V2FileContractTax(renewal.NewContract))
			},
		},
		{
			desc: "invalid renewal - total payout exceeding parent",
			renewFn: func(txn *types.V2Transaction) {
				// transfers part of the renter payout to the host
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				renewal.FinalRenterOutput.Value = renewal.FinalRenterOutput.Value.Add(types.Siacoins(1))
			},
			errString: "does not match existing contract payout",
		},
		{
			desc: "invalid renewal - total payout less than parent",
			renewFn: func(txn *types.V2Transaction) {
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				renewal.RenterRollover = renewal.RenterRollover.Sub(types.Siacoins(1))
				txn.SiacoinOutputs[0].Value = txn.SiacoinInputs[0].Parent.SiacoinOutput.Value.Sub(types.Siacoins(1)).Sub(cs.V2FileContractTax(renewal.NewContract))
			},
			errString: "does not match existing contract payout",
		},
		{
			desc: "invalid renewal - total payout less than parent - no rollover",
			renewFn: func(txn *types.V2Transaction) {
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				renewal.FinalRenterOutput.Value = renewal.RenterRollover.Sub(types.Siacoins(1))
				renewal.FinalHostOutput.Value = renewal.HostRollover
				renewal.RenterRollover = types.ZeroCurrency
				renewal.HostRollover = types.ZeroCurrency
				txn.SiacoinOutputs[0].Value = txn.SiacoinInputs[0].Parent.SiacoinOutput.Value.Sub(renewal.FinalRenterOutput.Value).Sub(renewal.FinalHostOutput.Value).Sub(cs.V2FileContractTax(renewal.NewContract))
			},
			errString: "siacoin inputs (1 KS) do not equal outputs (1.001 KS)", // this is an inputs != outputs error because the renewal is validated there first
		},
		{
			desc: "invalid renewal - bad new contract renter signature",
			renewFn: func(txn *types.V2Transaction) {
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				renewal.NewContract.RenterSignature[0] ^= 1
			},
			errString: "invalid renter signature",
		},
		{
			desc: "invalid renewal - bad new contract host signature",
			renewFn: func(txn *types.V2Transaction) {
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				renewal.NewContract.HostSignature[0] ^= 1
			},
			errString: "invalid host signature",
		},
		{
			desc: "invalid renewal - different host key",
			renewFn: func(txn *types.V2Transaction) {
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				sk := types.GeneratePrivateKey()
				renewal.NewContract.HostPublicKey = sk.PublicKey()
				contractSigHash := cs.ContractSigHash(renewal.NewContract)
				renewal.NewContract.HostSignature = sk.SignHash(contractSigHash)
			},
			errString: "changes host public key",
		},
		{
			desc: "invalid renewal - different renter key",
			renewFn: func(txn *types.V2Transaction) {
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				sk := types.GeneratePrivateKey()
				renewal.NewContract.RenterPublicKey = sk.PublicKey()
				contractSigHash := cs.ContractSigHash(renewal.NewContract)
				renewal.NewContract.RenterSignature = sk.SignHash(contractSigHash)
			},
			errString: "changes renter public key",
		},
		{
			desc: "invalid renewal - not enough host funds",
			renewFn: func(txn *types.V2Transaction) {
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				renewal.HostRollover = renewal.NewContract.MissedHostValue.Div64(2)
				// do not adjust the change output
			},
			errString: "do not equal outputs",
		},
		{
			desc: "invalid renewal - not enough renter funds",
			renewFn: func(txn *types.V2Transaction) {
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				renewal.RenterRollover = renewal.NewContract.RenterOutput.Value.Div64(2)
				// do not adjust the change output
			},
			errString: "do not equal outputs",
		},
		{
			desc: "invalid renewal - host rollover escape",
			renewFn: func(txn *types.V2Transaction) {
				// tests that the file contract renewal rollover cannot be used
				// outside of the new file contract. i.e. a siacoin output should
				// not be able to be created using the funds from a rollover. This
				// ensures that the maturity delay is enforced for renewals.
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				renewal.NewContract.HostOutput.Value = types.Siacoins(1)
				renewal.NewContract.MissedHostValue = types.Siacoins(1)
				// adjust the file contract tax
				txn.SiacoinOutputs[0].Value = txn.SiacoinInputs[0].Parent.SiacoinOutput.Value.Sub(cs.V2FileContractTax(renewal.NewContract))
				escapeAmount := renewal.HostRollover.Sub(renewal.NewContract.HostOutput.Value)
				txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{Value: escapeAmount, Address: types.VoidAddress})
			},
			errString: "exceeding new contract cost",
		},
		{
			desc: "invalid renewal - renter rollover escape",
			renewFn: func(txn *types.V2Transaction) {
				// tests that the file contract renewal rollover cannot be used
				// outside of the new file contract. i.e. a siacoin output should
				// not be able to be created using the funds from a rollover. This
				// ensures that the maturity delay is enforced for renewals.
				renewal := txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
				renewal.NewContract.RenterOutput.Value = types.Siacoins(1)
				// adjust the file contract tax
				txn.SiacoinOutputs[0].Value = txn.SiacoinInputs[0].Parent.SiacoinOutput.Value.Sub(cs.V2FileContractTax(renewal.NewContract))
				escapeAmount := renewal.RenterRollover.Sub(renewal.NewContract.RenterOutput.Value)
				txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{Value: escapeAmount, Address: types.VoidAddress})
			},
			errString: "exceeding new contract cost",
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			newContract := types.V2FileContract{
				ProofHeight:      100,
				ExpirationHeight: 150,
				RenterPublicKey:  pk.PublicKey(),
				HostPublicKey:    pk.PublicKey(),
				HostOutput: types.SiacoinOutput{
					Address: addr, Value: types.Siacoins(10),
				},
				RenterOutput: types.SiacoinOutput{
					Address: addr, Value: types.Siacoins(10),
				},
				MissedHostValue: types.Siacoins(10),
			}
			newContract.RenterSignature = pk.SignHash(cs.ContractSigHash(newContract))
			newContract.HostSignature = pk.SignHash(cs.ContractSigHash(newContract))

			renewTxn := types.V2Transaction{
				FileContractResolutions: []types.V2FileContractResolution{{
					Parent: fces[contractID].Copy(),
					Resolution: &types.V2FileContractRenewal{
						FinalRenterOutput: types.SiacoinOutput{Address: fc.RenterOutput.Address, Value: types.ZeroCurrency},
						FinalHostOutput:   types.SiacoinOutput{Address: fc.HostOutput.Address, Value: types.ZeroCurrency},
						NewContract:       newContract,
						RenterRollover:    types.Siacoins(10),
						HostRollover:      types.Siacoins(10),
					},
				}},
				SiacoinInputs: []types.V2SiacoinInput{{
					Parent: genesisOutput.Copy(),
					SatisfiedPolicy: types.SatisfiedPolicy{
						Policy: types.AnyoneCanSpend(),
					},
				}},
				SiacoinOutputs: []types.SiacoinOutput{{
					Address: addr,
					Value:   genesisOutput.SiacoinOutput.Value.Sub(cs.V2FileContractTax(newContract)),
				}},
			}
			resolution, ok := renewTxn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal)
			if !ok {
				t.Fatal("expected renewal resolution")
			}

			// modify the renewal
			test.renewFn(&renewTxn)

			// sign the renewal
			sigHash := cs.RenewalSigHash(*resolution)
			resolution.RenterSignature = pk.SignHash(sigHash)
			resolution.HostSignature = pk.SignHash(sigHash)
			// apply the renewal
			ms := NewMidState(cs)
			err := ValidateV2Transaction(ms, renewTxn)
			switch {
			case test.errString != "" && err == nil:
				t.Fatal("expected error")
			case test.errString != "" && test.errString == "":
				t.Fatalf("received error %q, missing error string to compare", err)
			case test.errString != "" && !strings.Contains(err.Error(), test.errString):
				t.Fatalf("expected error %q to contain %q", err, test.errString)
			case test.errString == "" && err != nil:
				t.Fatalf("unexpected error: %q", err)
			}
		})
	}
}

func TestValidateTransactionElements(t *testing.T) {
	n, genesisBlock := testnet()
	n.InitialTarget = types.BlockID{0xFF}
	n.HardforkV2.AllowHeight = 0
	n.HardforkV2.RequireHeight = 0

	giftPrivateKey := types.GeneratePrivateKey()
	giftPublicKey := giftPrivateKey.PublicKey()
	giftPolicy := types.PolicyPublicKey(giftPublicKey)
	giftAddress := types.StandardAddress(giftPublicKey)

	renterPrivateKey := types.GeneratePrivateKey()
	renterPublicKey := renterPrivateKey.PublicKey()
	hostPrivateKey := types.GeneratePrivateKey()
	hostPublicKey := hostPrivateKey.PublicKey()

	giftAmountSC := types.Siacoins(100)
	giftAmountSF := uint64(100)
	v1GiftFC := prepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), 100, 100, types.VoidAddress)
	v1GiftFC.Filesize = 65
	v1GiftFC.FileMerkleRoot = blake2b.SumPair((State{}).StorageProofLeafHash([]byte{1}), (State{}).StorageProofLeafHash([]byte{2}))
	v2GiftFC := types.V2FileContract{
		Capacity:         v1GiftFC.Filesize,
		Filesize:         v1GiftFC.Filesize,
		FileMerkleRoot:   v1GiftFC.FileMerkleRoot,
		ProofHeight:      20,
		ExpirationHeight: 30,
		RenterOutput:     v1GiftFC.ValidProofOutputs[0],
		HostOutput:       v1GiftFC.ValidProofOutputs[1],
		MissedHostValue:  v1GiftFC.MissedProofOutputs[1].Value,
		TotalCollateral:  v1GiftFC.Payout,
		RenterPublicKey:  renterPublicKey,
		HostPublicKey:    hostPublicKey,
	}
	contractCost := v2GiftFC.RenterOutput.Value.Add(v2GiftFC.HostOutput.Value).Add(n.GenesisState().V2FileContractTax(v2GiftFC))

	giftTxn := types.V2Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: giftAddress, Value: giftAmountSC},
			{Address: giftAddress, Value: contractCost},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Address: giftAddress, Value: giftAmountSF},
		},
		FileContracts: []types.V2FileContract{v2GiftFC},
	}

	genesisBlock.Transactions = nil
	genesisBlock.V2 = &types.V2BlockData{
		Transactions: []types.V2Transaction{giftTxn},
	}

	_, au := ApplyBlock(n.GenesisState(), genesisBlock, V1BlockSupplement{}, time.Time{})
	sces := make([]types.SiacoinElement, len(au.SiacoinElementDiffs()))
	for i := range sces {
		sces[i] = au.SiacoinElementDiffs()[i].SiacoinElement.Copy()
	}
	sfes := make([]types.SiafundElement, len(au.SiafundElementDiffs()))
	for i := range sfes {
		sfes[i] = au.SiafundElementDiffs()[i].SiafundElement.Copy()
	}
	fces := make([]types.V2FileContractElement, len(au.V2FileContractElementDiffs()))
	for i := range fces {
		fces[i] = au.V2FileContractElementDiffs()[i].V2FileContractElement.Copy()
	}
	cies := []types.ChainIndexElement{au.ChainIndexElement()}

	db, cs := newConsensusDB(n, genesisBlock)

	fc := v2GiftFC
	fc.TotalCollateral = fc.HostOutput.Value

	rev1 := v2GiftFC
	rev1.RevisionNumber++
	minerFee := types.Siacoins(1)
	b := types.Block{
		ParentID:  genesisBlock.ID(),
		Timestamp: types.CurrentTimestamp(),
		V2: &types.V2BlockData{
			Height: 1,
			Transactions: []types.V2Transaction{{
				SiacoinInputs: []types.V2SiacoinInput{{
					Parent:          sces[0].Copy(),
					SatisfiedPolicy: types.SatisfiedPolicy{Policy: giftPolicy},
				}},
				SiafundInputs: []types.V2SiafundInput{{
					Parent:          sfes[0].Copy(),
					ClaimAddress:    types.VoidAddress,
					SatisfiedPolicy: types.SatisfiedPolicy{Policy: giftPolicy},
				}},
				SiacoinOutputs: []types.SiacoinOutput{
					{Value: giftAmountSC.Sub(minerFee).Sub(contractCost), Address: giftAddress},
				},
				SiafundOutputs: []types.SiafundOutput{
					{Value: giftAmountSF / 2, Address: giftAddress},
					{Value: giftAmountSF / 2, Address: types.VoidAddress},
				},
				FileContracts: []types.V2FileContract{fc},
				FileContractRevisions: []types.V2FileContractRevision{
					{Parent: au.V2FileContractElementDiffs()[0].V2FileContractElement.Copy(), Revision: rev1},
				},
				MinerFee: minerFee,
			}},
		},
		MinerPayouts: []types.SiacoinOutput{{
			Address: types.VoidAddress,
			Value:   cs.BlockReward().Add(minerFee),
		}},
	}

	// validate elements
	txn := b.V2.Transactions[0]
	if err := cs.Elements.ValidateTransactionElements(txn); err != nil {
		t.Fatal(err)
	}
	// validate that corrupting an element results in an error
	for _, fn := range []func(){
		func() { txn.SiacoinInputs[0].Parent.ID[0] ^= 1 },
		func() { txn.SiafundInputs[0].Parent.StateElement.LeafIndex ^= 1 },
		func() { txn.FileContractRevisions[0].Parent.StateElement.MerkleProof[0][0] ^= 1 },
	} {
		fn()
		if err := cs.Elements.ValidateTransactionElements(txn); err == nil || !strings.Contains(err.Error(), "invalid Merkle proof") {
			t.Fatal("expected invalid Merkle proof error, got", err)
		}
		fn()
	}

	cs, testAU := ApplyBlock(cs, b, db.supplementTipBlock(b), time.Now())
	db.applyBlock(testAU)
	updateProofs(testAU, sces, sfes, fces, cies)

	testSces := make([]types.SiacoinElement, len(testAU.SiacoinElementDiffs()))
	for i := range testSces {
		testSces[i] = testAU.SiacoinElementDiffs()[i].SiacoinElement.Copy()
	}
	testSfes := make([]types.SiafundElement, len(testAU.SiafundElementDiffs()))
	for i := range testSfes {
		testSfes[i] = testAU.SiafundElementDiffs()[i].SiafundElement.Copy()
	}
	testFces := make([]types.V2FileContractElement, len(testAU.V2FileContractElementDiffs()))
	for i := range testFces {
		testFces[i] = testAU.V2FileContractElementDiffs()[i].V2FileContractElement.Copy()
	}
	cies = append(cies, testAU.ChainIndexElement())

	// mine empty blocks
	blockID := b.ID()
	for i := uint64(0); i < v2GiftFC.ProofHeight; i++ {
		b := types.Block{
			ParentID:  blockID,
			Timestamp: types.CurrentTimestamp(),
			V2: &types.V2BlockData{
				Height: cs.Index.Height + 1,
			},
			MinerPayouts: []types.SiacoinOutput{{
				Address: types.VoidAddress,
				Value:   cs.BlockReward(),
			}},
		}
		b.V2.Commitment = cs.Commitment(b.MinerPayouts[0].Address, b.Transactions, b.V2Transactions())

		findBlockNonce(cs, &b)
		if err := ValidateBlock(cs, b, db.supplementTipBlock(b)); err != nil {
			t.Fatal(err)
		}
		cs, au = ApplyBlock(cs, b, db.supplementTipBlock(b), time.Now())
		db.applyBlock(au)
		updateProofs(au, sces, sfes, fces, cies)
		updateProofs(au, testSces, testSfes, testFces, nil)
		cies = append(cies, au.ChainIndexElement())

		blockID = b.ID()
	}

	// construct a transaction that resolves the file contract
	txn = types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent: testFces[0].Copy(),
			Resolution: &types.V2StorageProof{
				ProofIndex: cies[len(cies)-2].Copy(),
				Leaf:       [64]byte{1},
				Proof:      []types.Hash256{cs.StorageProofLeafHash([]byte{2})},
			},
		}},
	}
	if err := cs.Elements.ValidateTransactionElements(txn); err != nil {
		t.Fatal(err)
	}
	for _, fn := range []func(){
		func() { txn.FileContractResolutions[0].Resolution.(*types.V2StorageProof).ProofIndex.ID[0] ^= 1 },
		func() { txn.FileContractResolutions[0].Parent.StateElement.MerkleProof[0][0] ^= 1 },
	} {
		fn()
		if err := cs.Elements.ValidateTransactionElements(txn); err == nil || !strings.Contains(err.Error(), "invalid Merkle proof") {
			t.Fatal("expected invalid Merkle proof error, got", err)
		}
		fn()
	}
}

func TestValidateFinalCutMinerPayout(t *testing.T) {
	n, _ := testnet()
	cs := n.GenesisState()
	cs.Index.Height = n.HardforkV2.FinalCutHeight - 2
	txn := types.V2Transaction{MinerFee: types.Siacoins(1)}
	b := types.Block{
		ParentID:  cs.Index.ID,
		Timestamp: types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{
			Address: types.VoidAddress,
			Value:   cs.BlockReward().Add(txn.MinerFee),
		}},
		V2: &types.V2BlockData{
			Height:       cs.Index.Height + 1,
			Transactions: []types.V2Transaction{txn},
		},
	}
	if err := ValidateOrphan(cs, b); err != nil {
		t.Fatal(err)
	}
	// omit payout value; should fail below final cut height
	b.MinerPayouts[0].Value = types.ZeroCurrency
	if err := ValidateOrphan(cs, b); err == nil || !strings.Contains(err.Error(), "miner payout has zero value") {
		t.Fatal(err)
	}
	// after final cut height, should succeed
	cs.Index.Height++
	b.V2.Height++
	if err := ValidateOrphan(cs, b); err != nil {
		t.Fatal(err)
	}
}

func TestValidateHeader(t *testing.T) {
	n, genesisBlock := testnet()
	n.InitialTarget = types.BlockID{0xFF}
	n.HardforkV2.FinalCutHeight = 1
	n.HardforkASIC.Height = 1
	n.HardforkASIC.NonceFactor = 2

	tests := []struct {
		desc      string
		mutate    func(h *types.BlockHeader, s *State)
		errString string
	}{
		{
			desc: "valid header",
			mutate: func(h *types.BlockHeader, s *State) {
				// no mutation
			},
		},
		{
			desc: "invalid header - nonce factor",
			mutate: func(h *types.BlockHeader, s *State) {
				h.Nonce = 1
			},
			errString: "nonce not divisible by required factor",
		},
		{
			desc: "invalid header - wrong parentID",
			mutate: func(h *types.BlockHeader, s *State) {
				h.ParentID = types.BlockID{}
			},
			errString: "wrong parent ID",
		},
		{
			desc: "invalid header - timestamp too old",
			mutate: func(h *types.BlockHeader, s *State) {
				h.Timestamp = time.Unix(0, 0).UTC()
			},
			errString: "timestamp too far in the past",
		},
		{
			desc: "invalid header - insufficient work",
			mutate: func(h *types.BlockHeader, s *State) {
				// Max diff
				s.Difficulty = Work{n: [32]byte{0xff}}
			},
			errString: "insufficient work",
		},
	}

	for _, test := range tests {
		_, s := newConsensusDB(n, genesisBlock)
		h := types.BlockHeader{
			ParentID:  s.Index.ID,
			Timestamp: time.Now(),
		}
		findHeaderNonce(s, &h)
		t.Run(test.desc, func(t *testing.T) {
			test.mutate(&h, &s)

			err := ValidateHeader(s, h)

			// check the valid case
			if test.errString == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		})
	}
}

func TestValidateMinerPayouts(t *testing.T) {
	n, genesisBlock := testnet()

	// Test all V1 conditions
	tests := []struct {
		desc      string
		mutate    func(b *types.Block, s *State)
		errString string
	}{
		{
			desc: "valid V1 block",
			mutate: func(b *types.Block, s *State) {
				// no mutation
			},
		},
		{
			desc: "valid V1 block - V1 transaction with single MinerFee",
			mutate: func(b *types.Block, s *State) {
				b.Transactions = []types.Transaction{
					{
						MinerFees: []types.Currency{
							types.Siacoins(1),
						},
					},
				}
				b.MinerPayouts[0].Value = b.MinerPayouts[0].Value.Add(types.Siacoins(1))
			},
		},
		{
			desc: "valid V1 block - V1 transaction with multiple MinerFee",
			mutate: func(b *types.Block, s *State) {
				b.Transactions = []types.Transaction{
					{
						MinerFees: []types.Currency{
							types.Siacoins(1),
							types.Siacoins(1),
						},
					},
				}
				b.MinerPayouts[0].Value = b.MinerPayouts[0].Value.Add(types.Siacoins(2))
			},
		},
		{
			desc: "valid V1 block - multiple V1 transactions with single MinerFee",
			mutate: func(b *types.Block, s *State) {
				b.Transactions = []types.Transaction{
					{
						MinerFees: []types.Currency{
							types.Siacoins(1),
						},
					},
					{
						MinerFees: []types.Currency{
							types.Siacoins(1),
						},
					},
				}
				b.MinerPayouts[0].Value = b.MinerPayouts[0].Value.Add(types.Siacoins(2))
			},
		},
		{
			desc: "valid V1 block - multiple V1 transactions with multiple MinerFee",
			mutate: func(b *types.Block, s *State) {
				b.Transactions = []types.Transaction{
					{
						MinerFees: []types.Currency{
							types.Siacoins(1),
							types.Siacoins(1),
						},
					},
					{
						MinerFees: []types.Currency{
							types.Siacoins(1),
							types.Siacoins(1),
						},
					},
				}
				b.MinerPayouts[0].Value = b.MinerPayouts[0].Value.Add(types.Siacoins(4))
			},
		},
		{
			desc: "invalid V1 block - V1 transaction fee has zero value",
			mutate: func(b *types.Block, s *State) {
				txn := types.Transaction{
					MinerFees: []types.Currency{
						types.ZeroCurrency,
					},
				}
				b.Transactions = append(b.Transactions, txn)
			},
			errString: "transaction fee has zero value",
		},
		{
			desc: "invalid V1 block - V1 transaction fees overflow",
			mutate: func(b *types.Block, s *State) {
				txn := types.Transaction{
					MinerFees: []types.Currency{
						types.MaxCurrency,
					},
				}
				b.Transactions = append(b.Transactions, txn)
			},
			errString: "transaction fees overflow",
		},
		{
			desc: "invalid V1 block - miner payout has zero value",
			mutate: func(b *types.Block, s *State) {
				b.MinerPayouts = []types.SiacoinOutput{
					{
						Value: types.ZeroCurrency,
					},
				}
			},
			errString: "miner payout has zero value",
		},
		{
			desc: "invalid V1 block - miner payouts overflow",
			mutate: func(b *types.Block, s *State) {
				b.MinerPayouts = []types.SiacoinOutput{
					{
						Value: types.Siacoins(1),
					},
					{
						Value: types.MaxCurrency,
					},
				}
			},
			errString: "miner payouts overflow",
		},
		{
			desc: "invalid V1 block - miner payouts too low",
			mutate: func(b *types.Block, s *State) {
				b.MinerPayouts = []types.SiacoinOutput{
					{
						Value: types.Siacoins(1),
					},
				}
			},
			errString: "miner payout sum (1 SC) does not match block reward + fees (300 KS)",
		},
		{
			desc: "invalid V1 block - miner payouts too high",
			mutate: func(b *types.Block, s *State) {
				b.MinerPayouts = append(b.MinerPayouts, types.SiacoinOutput{
					Value: types.Siacoins(1),
				})
			},
			errString: "miner payout sum (300.001 KS) does not match block reward + fees (300 KS)",
		},
	}

	for _, test := range tests {
		_, s := newConsensusDB(n, genesisBlock)
		b := types.Block{
			ParentID:  s.Index.ID,
			Timestamp: time.Now(),
			MinerPayouts: []types.SiacoinOutput{
				{
					Value:   s.BlockReward(),
					Address: types.VoidAddress,
				},
			},
		}
		findBlockNonce(s, &b)
		t.Run(test.desc, func(t *testing.T) {
			test.mutate(&b, &s)

			err := validateMinerPayouts(s, b)

			// check the valid case
			if test.errString == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		})
	}

	// Test all V2 conditions
	tests = []struct {
		desc      string
		mutate    func(b *types.Block, s *State)
		errString string
	}{
		{
			desc: "valid V2 block",
			mutate: func(b *types.Block, s *State) {
				// no mutation
			},
		},
		{
			desc: "valid V2 block - V2 transaction with valid MinerFee",
			mutate: func(b *types.Block, s *State) {
				b.V2.Transactions = []types.V2Transaction{
					{
						MinerFee: types.Siacoins(1),
					},
				}
				b.MinerPayouts[0].Value = b.MinerPayouts[0].Value.Add(types.Siacoins(1))
			},
		},
		{
			desc: "valid V2 block - V2 transactions with valid MinerFee",
			mutate: func(b *types.Block, s *State) {
				b.V2.Transactions = []types.V2Transaction{
					{
						MinerFee: types.Siacoins(1),
					},
					{
						MinerFee: types.Siacoins(1),
					},
				}
				b.MinerPayouts[0].Value = b.MinerPayouts[0].Value.Add(types.Siacoins(2))
			},
		},
		{
			desc: "invalid V2 block - V2 transaction fees overflow",
			mutate: func(b *types.Block, s *State) {
				txn := types.V2Transaction{
					MinerFee: types.MaxCurrency,
				}
				b.V2.Transactions = []types.V2Transaction{txn}
			},
			errString: "v2 transaction fees overflow",
		},
		{
			desc: "invalid V2 block - V1/V2 mixed transaction fees overflow",
			mutate: func(b *types.Block, s *State) {
				txn := types.Transaction{
					MinerFees: []types.Currency{
						types.MaxCurrency.Sub(s.BlockReward()).Sub(types.Siacoins(1)),
					},
				}
				b.Transactions = append(b.Transactions, txn)

				txn2 := types.V2Transaction{
					MinerFee: types.MaxCurrency,
				}
				b.V2.Transactions = []types.V2Transaction{txn2}
			},
			errString: "v2 transaction fees overflow",
		},
		{
			desc: "invalid V2 block - V2 block with no MinerPayouts",
			mutate: func(b *types.Block, s *State) {
				b.MinerPayouts = []types.SiacoinOutput{}
			},
			errString: "block must have exactly one miner payout",
		},
		{
			desc: "invalid V2 block - V2 block with multiple MinerPayouts",
			mutate: func(b *types.Block, s *State) {
				b.MinerPayouts = []types.SiacoinOutput{{}, {}}
			},
			errString: "block must have exactly one miner payout",
		},
		{
			desc: "invalid V2 block - V2 block with 0 value MinerPayout before FinalCutHeight",
			mutate: func(b *types.Block, s *State) {
				b.MinerPayouts = []types.SiacoinOutput{
					{
						Value: types.ZeroCurrency,
					},
				}
			},
			errString: "miner payout has zero value",
		},
		{
			desc: "valid V2 block - V2 block with 0 value MinerPayout after FinalCutHeight",
			mutate: func(b *types.Block, s *State) {
				b.MinerPayouts = []types.SiacoinOutput{
					{
						Value: types.ZeroCurrency,
					},
				}
				s.Network.HardforkV2.FinalCutHeight = 1
			},
		},
		{
			desc: "invalid V2 block - V2 block miner payouts too low before FinalCutHeight",
			mutate: func(b *types.Block, s *State) {
				b.MinerPayouts = []types.SiacoinOutput{
					{
						Value: types.Siacoins(1),
					},
				}
			},
			errString: "miner payout sum (1 SC) does not match block reward + fees (300 KS)",
		},
		{
			desc: "invalid V2 block - V2 block miner payouts too high before FinalCutHeight",
			mutate: func(b *types.Block, s *State) {
				b.MinerPayouts = []types.SiacoinOutput{
					{
						Value: types.Siacoins(300001),
					},
				}
			},
			errString: "miner payout sum (300.001 KS) does not match block reward + fees (300 KS)",
		},
	}

	for _, test := range tests {
		_, s := newConsensusDB(n, genesisBlock)
		b := types.Block{
			ParentID:  s.Index.ID,
			Timestamp: time.Now(),
			MinerPayouts: []types.SiacoinOutput{
				{
					Value:   s.BlockReward(),
					Address: types.VoidAddress,
				},
			},
			// Initialize any V2BlockData to trigger `if v.V2 != nil` condition
			V2: &types.V2BlockData{
				// Transactions: []types.V2Transaction{},
			},
		}
		findBlockNonce(s, &b)
		t.Run(test.desc, func(t *testing.T) {
			test.mutate(&b, &s)

			err := validateMinerPayouts(s, b)

			// check the valid case
			if test.errString == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		})
	}
}

func TestValidateOrphan(t *testing.T) {
	n, genesisBlock := testnet()

	tests := []struct {
		desc      string
		mutate    func(b *types.Block, s *State)
		errString string
	}{
		{
			desc: "valid V1 block",
			mutate: func(b *types.Block, s *State) {
				// no mutation
			},
		},
		{
			desc: "valid V1 block - include Transactions",
			mutate: func(b *types.Block, s *State) {
				b.Transactions = []types.Transaction{
					{
						ArbitraryData: [][]byte{{0x00}},
					},
					{
						ArbitraryData: [][]byte{{0x01}},
					},
				}
			},
		},
		{
			desc: "valid V1 block - include a single max sized Transaction",
			mutate: func(b *types.Block, s *State) {
				txn := types.Transaction{
					ArbitraryData: [][]byte{{}},
				}
				overhead := s.TransactionWeight(txn)

				txn.ArbitraryData[0] = make([]byte, s.MaxBlockWeight()-overhead)
				b.Transactions = []types.Transaction{txn}
			},
		},
		{
			desc: "valid V1 block - include two transactions that sum to max weight",
			mutate: func(b *types.Block, s *State) {
				txn := types.Transaction{
					ArbitraryData: [][]byte{{}},
				}
				txn2 := types.Transaction{
					ArbitraryData: [][]byte{{}},
				}
				overhead := s.TransactionWeight(txn)

				txn.ArbitraryData[0] = make([]byte, s.MaxBlockWeight()-overhead*2)
				b.Transactions = []types.Transaction{txn, txn2}
			},
		},
		{
			desc: "invalid V1 block - include two Transactions that sum to greater than max weight",
			mutate: func(b *types.Block, s *State) {
				txn := types.Transaction{
					ArbitraryData: [][]byte{{}},
				}
				txn2 := types.Transaction{
					ArbitraryData: [][]byte{{}},
				}
				overhead := s.TransactionWeight(txn)

				txn.ArbitraryData[0] = make([]byte, s.MaxBlockWeight()-overhead*2+1)
				b.Transactions = []types.Transaction{txn, txn2}
			},
			errString: "block exceeds maximum weight (2000001 > 2000000)",
		},
		{
			desc: "invalid V1 block - include two max weight Transactions",
			mutate: func(b *types.Block, s *State) {
				txn := types.Transaction{
					ArbitraryData: [][]byte{{}},
				}
				overhead := s.TransactionWeight(txn)

				txn.ArbitraryData[0] = make([]byte, s.MaxBlockWeight()-overhead)

				b.Transactions = []types.Transaction{txn, txn}
			},
			errString: "block exceeds maximum weight (4000000 > 2000000)",
		},
		{
			desc: "invalid V1 block - include a single over sized Transaction",
			mutate: func(b *types.Block, s *State) {
				txn := types.Transaction{
					ArbitraryData: [][]byte{{}},
				}
				overhead := s.TransactionWeight(txn)

				txn.ArbitraryData[0] = make([]byte, s.MaxBlockWeight()-overhead+1)
				b.Transactions = []types.Transaction{txn}
			},
			errString: "block exceeds maximum weight (2000001 > 2000000)",
		},
		{
			desc: "invalid V1 block - invalid miner payouts",
			mutate: func(b *types.Block, s *State) {
				b.MinerPayouts = []types.SiacoinOutput{
					{Value: types.Siacoins(1)},
				}
			},
			errString: "miner payout sum (1 SC) does not match block reward + fees (300 KS)",
		},
		{
			desc: "invalid V1 block - invalid header",
			mutate: func(b *types.Block, s *State) {
				b.ParentID = types.BlockID{0x00}
			},
			errString: "block has wrong parent ID",
		},
		{
			desc: "valid V2 block",
			mutate: func(b *types.Block, s *State) {
				b.V2 = &types.V2BlockData{
					Height: s.Index.Height + 1,
				}
			},
		},
		{
			desc: "valid V2 block - include V1 Transaction",
			mutate: func(b *types.Block, s *State) {
				b.Transactions = []types.Transaction{
					{ArbitraryData: [][]byte{{0x01}}},
				}
				b.V2 = &types.V2BlockData{
					Height: s.Index.Height + 1,
				}
			},
		},
		{
			desc: "valid V2 block - include V2Transaction",
			mutate: func(b *types.Block, s *State) {
				b.V2 = &types.V2BlockData{
					Height: s.Index.Height + 1,
					Transactions: []types.V2Transaction{
						{
							ArbitraryData: []byte{0x01},
						},
					},
				}
			},
		},
		{
			desc: "valid V2 block - include V1 Transaction and V2Transaction",
			mutate: func(b *types.Block, s *State) {
				b.Transactions = []types.Transaction{
					{ArbitraryData: [][]byte{{0x01}}},
				}
				b.V2 = &types.V2BlockData{
					Height: s.Index.Height + 1,
					Transactions: []types.V2Transaction{
						{
							ArbitraryData: []byte{0x01},
						},
					},
				}
			},
		},
		{
			desc: "valid V2 block - include max sized V2Transaction",
			mutate: func(b *types.Block, s *State) {
				txn := types.V2Transaction{
					ArbitraryData: []byte{},
				}
				overhead := s.V2TransactionWeight(txn)

				txn.ArbitraryData = make([]byte, s.MaxBlockWeight()-overhead)

				b.V2 = &types.V2BlockData{
					Height:       s.Index.Height + 1,
					Transactions: []types.V2Transaction{txn},
				}
			},
		},
		{
			desc: "invalid V2 block - include over sized V2Transaction",
			mutate: func(b *types.Block, s *State) {
				txn := types.V2Transaction{
					ArbitraryData: []byte{},
				}
				overhead := s.V2TransactionWeight(txn)

				txn.ArbitraryData = make([]byte, s.MaxBlockWeight()-overhead+1)

				b.V2 = &types.V2BlockData{
					Height:       s.Index.Height + 1,
					Transactions: []types.V2Transaction{txn},
				}
			},
			errString: "block exceeds maximum weight (2000001 > 2000000)",
		},
		{
			desc: "invalid V2 block - include 2 max sized V2Transactions",
			mutate: func(b *types.Block, s *State) {
				txn := types.V2Transaction{
					ArbitraryData: []byte{},
				}
				overhead := s.V2TransactionWeight(txn)

				txn.ArbitraryData = make([]byte, s.MaxBlockWeight()-overhead)

				b.V2 = &types.V2BlockData{
					Height:       s.Index.Height + 1,
					Transactions: []types.V2Transaction{txn, txn},
				}
			},
			errString: "block exceeds maximum weight (4000000 > 2000000)",
		},
		{
			desc: "invalid V2 block - include max sized V1 Transaction and max sized V2Transaction",
			mutate: func(b *types.Block, s *State) {
				txn := types.Transaction{
					ArbitraryData: [][]byte{{}},
				}
				overhead := s.TransactionWeight(txn)
				txn.ArbitraryData[0] = make([]byte, s.MaxBlockWeight()-overhead)

				txn2 := types.V2Transaction{
					ArbitraryData: []byte{},
				}
				overhead = s.V2TransactionWeight(txn2)
				txn2.ArbitraryData = make([]byte, s.MaxBlockWeight()-overhead)

				b.Transactions = []types.Transaction{txn}
				b.V2 = &types.V2BlockData{
					Height:       s.Index.Height + 1,
					Transactions: []types.V2Transaction{txn2},
				}
			},
			errString: "block exceeds maximum weight (4000000 > 2000000)",
		},
		{
			desc: "valid V2 block - include V1 Transaction and V2Transaction that sum to max weight",
			mutate: func(b *types.Block, s *State) {
				txn := types.Transaction{
					ArbitraryData: [][]byte{{}},
				}
				txn2 := types.V2Transaction{
					ArbitraryData: []byte{},
				}
				overhead := s.TransactionWeight(txn)
				overhead += s.V2TransactionWeight(txn2)

				txn2.ArbitraryData = make([]byte, s.MaxBlockWeight()-overhead)
				b.Transactions = []types.Transaction{txn}
				b.V2 = &types.V2BlockData{
					Height:       s.Index.Height + 1,
					Transactions: []types.V2Transaction{txn2},
				}
			},
		},
		{
			desc: "invalid V2 block - include V1 Transaction and V2Transaction that exceed max weight",
			mutate: func(b *types.Block, s *State) {
				txn := types.Transaction{
					ArbitraryData: [][]byte{{}},
				}
				txn2 := types.V2Transaction{
					ArbitraryData: []byte{},
				}
				overhead := s.TransactionWeight(txn)
				overhead += s.V2TransactionWeight(txn2)

				txn2.ArbitraryData = make([]byte, s.MaxBlockWeight()-overhead+1)
				b.Transactions = []types.Transaction{txn}
				b.V2 = &types.V2BlockData{
					Height:       s.Index.Height + 1,
					Transactions: []types.V2Transaction{txn2},
				}
			},
			errString: "block exceeds maximum weight (2000001 > 2000000)",
		},
		{
			desc: "invalid V2 block - height too low",
			mutate: func(b *types.Block, s *State) {
				b.V2 = &types.V2BlockData{
					Height: s.Index.Height,
				}
			},
			errString: "block height does not increment parent height",
		},
		{
			desc: "invalid V2 block - height too high",
			mutate: func(b *types.Block, s *State) {
				b.V2 = &types.V2BlockData{
					Height: s.Index.Height + 2,
				}
			},
			errString: "block height does not increment parent height",
		},
		{
			desc: "invalid V2 block - invalid miner payouts",
			mutate: func(b *types.Block, s *State) {
				b.MinerPayouts = []types.SiacoinOutput{
					{Value: types.Siacoins(1)},
				}
				b.V2 = &types.V2BlockData{
					Height: s.Index.Height + 1,
				}
			},
			errString: "miner payout sum (1 SC) does not match block reward + fees (300 KS)",
		},
		{
			desc: "invalid V2 block - invalid header",
			mutate: func(b *types.Block, s *State) {
				b.ParentID = types.BlockID{0x00}
				b.V2 = &types.V2BlockData{
					Height: s.Index.Height + 1,
				}
			},
			errString: "block has wrong parent ID",
		},
	}

	for _, test := range tests {
		_, s := newConsensusDB(n, genesisBlock)
		b := types.Block{
			ParentID:  s.Index.ID,
			Timestamp: time.Now(),
			MinerPayouts: []types.SiacoinOutput{
				{
					Value:   s.BlockReward(),
					Address: types.VoidAddress,
				},
			},
		}
		findBlockNonce(s, &b)
		t.Run(test.desc, func(t *testing.T) {
			test.mutate(&b, &s)

			err := ValidateOrphan(s, b)

			// check the valid case
			if test.errString == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		})
	}
}

func TestValidateCurrencyOverflow(t *testing.T) {
	n, genesisBlock := testnet()

	// Test all V1 conditions
	tests := []struct {
		desc      string
		mutate    func(ms *MidState, txn *types.Transaction)
		errString string
	}{
		{
			desc: "valid Transaction",
			mutate: func(ms *MidState, txn *types.Transaction) {
				// no mutation
			},
		},
		{
			desc: "valid Transaction - include valid SiacoinOutput Values",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Address: types.VoidAddress,
							Value:   types.Siacoins(1),
						},
						{
							Address: types.VoidAddress,
							Value:   types.Siacoins(2),
						},
					},
				}
			},
		},
		{
			desc: "invalid Transaction - overflow SiacoinOutput Values",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Address: types.VoidAddress,
							Value:   types.NewCurrency64(1),
						},
						{
							Address: types.VoidAddress,
							Value:   types.MaxCurrency,
						},
					},
				}
			},
			errString: "transaction outputs exceed inputs",
		},
		{
			desc: "valid Transaction - include a valid SiafundOutput",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiafundOutputs: []types.SiafundOutput{
						{
							Value: 1,
						},
					},
				}
			},
		},
		{
			desc: "valid Transaction - include a valid max Value SiafundOutput",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiafundOutputs: []types.SiafundOutput{
						{
							Value: ms.base.SiafundCount(),
						},
					},
				}
			},
		},
		{
			desc: "valid Transaction - include two max Value SiafundOutputs",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiafundOutputs: []types.SiafundOutput{
						{
							Value: ms.base.SiafundCount(),
						},
						{
							Value: ms.base.SiafundCount(),
						},
					},
				}
			},
		},
		{
			desc: "invalid Transaction - include a SiafundOutput greater than max Value",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiafundOutputs: []types.SiafundOutput{
						{
							Value: ms.base.SiafundCount() + 1,
						},
					},
				}
			},
			errString: "transaction outputs exceed inputs",
		},
		{
			desc: "invalid Transaction - overflow FileContracts Payout Value",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					FileContracts: []types.FileContract{
						{
							Payout: types.MaxCurrency,
						},
						{
							Payout: types.NewCurrency64(1),
						},
					},
				}
			},
			errString: "transaction outputs exceed inputs",
		},
		{
			desc: "invalid Transaction - overflow FileContracts ValidProofOutputs Values",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					FileContracts: []types.FileContract{
						{
							ValidProofOutputs: []types.SiacoinOutput{
								{
									Value: types.MaxCurrency,
								},
								{
									Value: types.NewCurrency64(1),
								},
							},
						},
					},
				}
			},
			errString: "transaction outputs exceed inputs",
		},
		{
			desc: "invalid Transaction - overflow FileContracts MissedProofOutputs Values",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					FileContracts: []types.FileContract{
						{
							MissedProofOutputs: []types.SiacoinOutput{
								{
									Value: types.MaxCurrency,
								},
								{
									Value: types.NewCurrency64(1),
								},
							},
						},
					},
				}
			},
			errString: "transaction outputs exceed inputs",
		},
		{
			desc: "invalid Transaction - overflow FileContractRevisions ValidProofOutputs Values",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					FileContractRevisions: []types.FileContractRevision{
						{
							FileContract: types.FileContract{
								ValidProofOutputs: []types.SiacoinOutput{
									{
										Value: types.MaxCurrency,
									},
									{
										Value: types.NewCurrency64(1),
									},
								},
							},
						},
					},
				}
			},
			errString: "transaction outputs exceed inputs",
		},
		{
			desc: "invalid Transaction - overflow FileContractRevisions MissedProofOutputs Values",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					FileContractRevisions: []types.FileContractRevision{
						{
							FileContract: types.FileContract{
								MissedProofOutputs: []types.SiacoinOutput{
									{
										Value: types.MaxCurrency,
									},
									{
										Value: types.NewCurrency64(1),
									},
								},
							},
						},
					},
				}
			},
			errString: "transaction outputs exceed inputs",
		},
		{
			desc: "valid Transaction - include MinerFees that would overflow if checked",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					MinerFees: []types.Currency{
						types.MaxCurrency,
						types.MaxCurrency,
					},
				}
			},
		},
		{
			desc: "valid Transaction - populate each Value field",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value: types.Siacoins(1),
						},
					},
					SiafundOutputs: []types.SiafundOutput{
						{
							Value: 1,
						},
					},
					FileContracts: []types.FileContract{
						{
							Payout: types.Siacoins(1),
							ValidProofOutputs: []types.SiacoinOutput{
								{
									Value: types.Siacoins(1),
								},
							},
							MissedProofOutputs: []types.SiacoinOutput{
								{
									Value: types.Siacoins(1),
								},
							},
						},
					},
					FileContractRevisions: []types.FileContractRevision{
						{
							FileContract: types.FileContract{
								ValidProofOutputs: []types.SiacoinOutput{
									{
										Value: types.Siacoins(1),
									},
								},
								MissedProofOutputs: []types.SiacoinOutput{
									{
										Value: types.Siacoins(1),
									},
								},
							},
						},
					},
				}
			},
		},
		{
			desc: "valid Transaction - populate each Value field twice",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value: types.Siacoins(1),
						},
						{
							Value: types.Siacoins(2),
						},
					},
					SiafundOutputs: []types.SiafundOutput{
						{
							Value: 1,
						},
						{
							Value: 2,
						},
					},
					FileContracts: []types.FileContract{
						{
							Payout: types.Siacoins(1),
							ValidProofOutputs: []types.SiacoinOutput{
								{
									Value: types.Siacoins(1),
								},
								{
									Value: types.Siacoins(2),
								},
							},
							MissedProofOutputs: []types.SiacoinOutput{
								{
									Value: types.Siacoins(1),
								},
								{
									Value: types.Siacoins(2),
								},
							},
						},
					},
					FileContractRevisions: []types.FileContractRevision{
						{
							FileContract: types.FileContract{
								ValidProofOutputs: []types.SiacoinOutput{
									{
										Value: types.Siacoins(1),
									},
									{
										Value: types.Siacoins(2),
									},
								},
								MissedProofOutputs: []types.SiacoinOutput{
									{
										Value: types.Siacoins(1),
									},
									{
										Value: types.Siacoins(2),
									},
								},
							},
						},
					},
				}
			},
		},
		{
			desc: "invalid Transaction - overflow across multiple fields",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiacoinOutputs: []types.SiacoinOutput{{Value: types.MaxCurrency}},
					FileContracts:  []types.FileContract{{Payout: types.NewCurrency64(1)}},
				}
			},
			errString: "transaction outputs exceed inputs",
		},
		{
			desc: "invalid Transaction - valid SiafundOutput but overflow SiacoinOutput",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiafundOutputs: []types.SiafundOutput{{Value: 1}},
					SiacoinOutputs: []types.SiacoinOutput{
						{Value: types.MaxCurrency},
						{Value: types.NewCurrency64(1)},
					},
				}
			},
			errString: "transaction outputs exceed inputs",
		},
	}

	for _, test := range tests {
		_, s := newConsensusDB(n, genesisBlock)
		ms := NewMidState(s)
		txn := types.Transaction{}

		t.Run(test.desc, func(t *testing.T) {
			test.mutate(ms, &txn)

			err := validateCurrencyOverflow(ms, txn)

			// check the valid case
			if test.errString == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		})
	}
}

func TestValidateMinimumValues(t *testing.T) {
	n, genesisBlock := testnet()

	tests := []struct {
		desc      string
		mutate    func(ms *MidState, txn *types.Transaction)
		errString string
	}{
		{
			desc: "valid Transaction - empty",
			mutate: func(ms *MidState, txn *types.Transaction) {
				// no mutation
			},
		},
		{
			desc: "valid Transaction - non-zero SiacoinOutput",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{Value: types.Siacoins(1)},
					},
				}
			},
		},
		{
			desc: "invalid Transaction - zero SiacoinOutput",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{Value: types.ZeroCurrency},
					},
				}
			},
			errString: "transaction creates a zero-valued output",
		},
		{
			desc: "invalid Transaction - second SiacoinOutput is zero",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{Value: types.Siacoins(1)},
						{Value: types.ZeroCurrency},
					},
				}
			},
			errString: "transaction creates a zero-valued output",
		},
		{
			desc: "valid Transaction - non-zero FileContract Payout",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					FileContracts: []types.FileContract{
						{Payout: types.Siacoins(1)},
					},
				}
			},
		},
		{
			desc: "invalid Transaction - zero FileContract Payout",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					FileContracts: []types.FileContract{
						{Payout: types.ZeroCurrency},
					},
				}
			},
			errString: "transaction creates a zero-valued output",
		},
		{
			desc: "valid Transaction - non-zero SiafundOutput",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiafundOutputs: []types.SiafundOutput{
						{Value: 1},
					},
				}
			},
		},
		{
			desc: "invalid Transaction - zero SiafundOutput",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiafundOutputs: []types.SiafundOutput{
						{Value: 0},
					},
				}
			},
			errString: "transaction creates a zero-valued output",
		},
		{
			desc: "valid Transaction - non-zero MinerFee",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					MinerFees: []types.Currency{
						types.Siacoins(1),
					},
				}
			},
		},
		{
			desc: "invalid Transaction - zero MinerFee",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					MinerFees: []types.Currency{
						types.ZeroCurrency,
					},
				}
			},
			errString: "transaction creates a zero-valued output",
		},
		{
			desc: "valid Transaction - all fields set to non-zero",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{Value: types.Siacoins(1)},
					},
					FileContracts: []types.FileContract{
						{Payout: types.Siacoins(1)},
					},
					SiafundOutputs: []types.SiafundOutput{
						{Value: 1},
					},
					MinerFees: []types.Currency{
						types.Siacoins(1),
					},
				}
			},
		},
		{
			desc: "valid Transaction - all non-covered Currency fields set to zero",
			mutate: func(ms *MidState, txn *types.Transaction) {
				*txn = types.Transaction{
					FileContracts: []types.FileContract{
						{
							Payout: types.Siacoins(1),
							ValidProofOutputs: []types.SiacoinOutput{
								{
									Value: types.ZeroCurrency,
								},
							},
							MissedProofOutputs: []types.SiacoinOutput{
								{
									Value: types.ZeroCurrency,
								},
							},
						},
					},
					FileContractRevisions: []types.FileContractRevision{
						{
							FileContract: types.FileContract{
								ValidProofOutputs: []types.SiacoinOutput{
									{
										Value: types.ZeroCurrency,
									},
								},
								MissedProofOutputs: []types.SiacoinOutput{
									{
										Value: types.ZeroCurrency,
									},
								},
							},
						},
					},
				}
			},
		},
	}

	for _, test := range tests {
		_, s := newConsensusDB(n, genesisBlock)
		ms := NewMidState(s)
		txn := types.Transaction{}

		t.Run(test.desc, func(t *testing.T) {
			test.mutate(ms, &txn)

			err := validateMinimumValues(ms, txn)

			if test.errString == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		})
	}
}

func TestValidateSiacoins(t *testing.T) {
	n, genesisBlock := testnet()

	tests := []struct {
		desc      string
		mutate    func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement)
		errString string
	}{
		{
			desc: "valid Transaction - empty",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				// no mutation
			},
		},
		{
			desc: "valid Transaction - spend a StandardUnlockConditions UTXO",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value: types.Siacoins(1),
						},
					},
				}

			},
		},
		{
			desc: "valid Transaction - spend multiple UTXOs",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID:            types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{Value: types.Siacoins(1), Address: unlockConditions.UnlockHash()},
						},
						{
							ID:            types.SiacoinOutputID{0x02},
							SiacoinOutput: types.SiacoinOutput{Value: types.Siacoins(2), Address: unlockConditions.UnlockHash()},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{ParentID: types.SiacoinOutputID{0x01}, UnlockConditions: unlockConditions},
						{ParentID: types.SiacoinOutputID{0x02}, UnlockConditions: unlockConditions},
					},
					SiacoinOutputs: []types.SiacoinOutput{
						{Value: types.Siacoins(3)},
					},
				}
			},
		},
		{
			desc: "valid Transaction - spend a time locked UTXO as soon as possible",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.UnlockConditions{
					Timelock: ms.base.childHeight(),
					PublicKeys: []types.UnlockKey{
						key.PublicKey().UnlockKey(),
					},
					SignaturesRequired: 1,
				}

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value: types.Siacoins(1),
						},
					},
				}

			},
		},
		{
			desc: "valid Transaction - spend a time locked UTXO long after it unlocks",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.UnlockConditions{
					Timelock: 500000,
					PublicKeys: []types.UnlockKey{
						key.PublicKey().UnlockKey(),
					},
					SignaturesRequired: 1,
				}

				// Fake the current height
				ms.base.Index.Height = 1000000

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value: types.Siacoins(1),
						},
					},
				}

			},
		},
		{
			desc: "invalid Transaction - attempt to spend timelocked UTXO",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.UnlockConditions{
					Timelock: ms.base.childHeight() + 1,
					PublicKeys: []types.UnlockKey{
						key.PublicKey().UnlockKey(),
					},
					SignaturesRequired: 1,
				}

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value: types.Siacoins(1),
						},
					},
				}

			},
			errString: "siacoin input 0 has timelocked parent",
		},
		{
			desc: "invalid Transaction - attempt to spend a previously spent UTXO",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				ms.spends[types.SiacoinOutputID{0x01}] = types.TransactionID{0x00}

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value: types.Siacoins(1),
						},
					},
				}

			},
			errString: "siacoin input 0 double-spends parent output (previously spent in 0000000000000000000000000000000000000000000000000000000000000000)",
		},
		{
			desc: "invalid Transaction - attempt to spend a nonexistent UTXO",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value: types.Siacoins(1),
						},
					},
				}

			},
			errString: "siacoin input 0 spends nonexistent siacoin output 0100000000000000000000000000000000000000000000000000000000000000",
		},
		{
			desc: "invalid Transaction - attempt to spend with incorrect UnlockConditions",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: types.UnlockConditions{},
						},
					},
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value: types.Siacoins(1),
						},
					},
				}

			},
			errString: "siacoin input 0 claims incorrect unlock conditions for siacoin output 0100000000000000000000000000000000000000000000000000000000000000",
		},
		{
			desc: "valid Transaction - spend a UTXO at MaturityHeight",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
							MaturityHeight: ms.base.childHeight(),
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value: types.Siacoins(1),
						},
					},
				}

			},
		},
		{
			desc: "valid Transaction - spend a UTXO immediately after MaturityHeight",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				// Fake the current height
				ms.base.Index.Height = 2

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
							MaturityHeight: ms.base.childHeight(),
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value: types.Siacoins(1),
						},
					},
				}

			},
		},
		{
			desc: "invalid Transaction - attempt to spend a UTXO immediately before MaturityHeight",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
							MaturityHeight: ms.base.childHeight() + 1,
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value: types.Siacoins(1),
						},
					},
				}

			},
			errString: "siacoin input 0 has immature parent",
		},
		{
			desc: "valid Transaction - spend a UTXO to SiacoinOutput",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiacoinOutputs: []types.SiacoinOutput{
						{Value: types.Siacoins(1)},
					},
				}

			},
		},
		{
			desc: "valid Transaction - spend a UTXO to multiple SiacoinOutputs",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(2),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiacoinOutputs: []types.SiacoinOutput{
						{Value: types.Siacoins(1)},
						{Value: types.Siacoins(1)},
					},
				}

			},
		},
		{
			desc: "valid Transaction - spend a UTXO to FileContracts Payout",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					FileContracts: []types.FileContract{
						{
							Payout: types.Siacoins(1),
						},
					},
				}

			},
		},
		{
			desc: "valid Transaction - spend a UTXO to multiple FileContracts Payouts",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(2),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					FileContracts: []types.FileContract{
						{
							Payout: types.Siacoins(1),
						},
						{
							Payout: types.Siacoins(1),
						},
					},
				}

			},
		},
		{
			desc: "valid Transaction - spend a UTXO to MinerFee",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					MinerFees: []types.Currency{types.Siacoins(1)},
				}
			},
		},
		{
			desc: "valid Transaction - spend a UTXO to multiple MinerFees",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(2),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					MinerFees: []types.Currency{
						types.Siacoins(1),
						types.Siacoins(1),
					},
				}
			},
		},
		{
			desc: "valid Transaction - spend a UTXO to multiple SiacoinOutputs, Payouts and MinerFees",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(6),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					MinerFees: []types.Currency{
						types.Siacoins(1),
						types.Siacoins(1),
					},
					FileContracts: []types.FileContract{
						{
							Payout: types.Siacoins(1),
						},
						{
							Payout: types.Siacoins(1),
						},
					},
					SiacoinOutputs: []types.SiacoinOutput{
						{Value: types.Siacoins(1)},
						{Value: types.Siacoins(1)},
					},
				}
			},
		},
		{
			desc: "invalid Transaction - attempt to spend too much to SiacoinOutput",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiacoinOutputs: []types.SiacoinOutput{
						{Value: types.Siacoins(2)},
					},
				}

			},
			errString: "siacoin inputs (1 SC) do not equal outputs (2 SC)",
		},
		{
			desc: "invalid Transaction - attempt to spend too much to MinerFee",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					MinerFees: []types.Currency{
						types.Siacoins(2),
					},
				}

			},
			errString: "siacoin inputs (1 SC) do not equal outputs (2 SC)",
		},
		{
			desc: "invalid Transaction - attempt to spend too much to Payout",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					FileContracts: []types.FileContract{
						{
							Payout: types.Siacoins(2),
						},
					},
				}

			},
			errString: "siacoin inputs (1 SC) do not equal outputs (2 SC)",
		},
		{
			desc: "invalid Transaction - attempt to spend a UTXO to nowhere",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiacoinInputs: []types.SiacoinElement{
						{
							ID: types.SiacoinOutputID{0x01},
							SiacoinOutput: types.SiacoinOutput{
								Value:   types.Siacoins(1),
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiacoinInputs: []types.SiacoinInput{
						{
							ParentID:         types.SiacoinOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
				}
			},
			errString: "siacoin inputs (1 SC) do not equal outputs (0 SC)",
		},
	}

	for _, test := range tests {
		_, s := newConsensusDB(n, genesisBlock)
		ms := NewMidState(s)
		txn := types.Transaction{}
		ts := V1TransactionSupplement{}

		t.Run(test.desc, func(t *testing.T) {
			test.mutate(ms, &txn, &ts)

			err := validateSiacoins(ms, txn, ts)

			if test.errString == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		})
	}
}

func TestValidateSiafunds(t *testing.T) {
	n, genesisBlock := testnet()

	tests := []struct {
		desc      string
		mutate    func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement)
		errString string
	}{
		{
			desc: "valid Transaction - empty",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				// no mutation
			},
		},
		{
			desc: "valid Transaction - spend a StandardUnlockConditions UTXO",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiafundInputs: []types.SiafundElement{
						{
							ID: types.SiafundOutputID{0x01},
							SiafundOutput: types.SiafundOutput{
								Value:   1,
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiafundInputs: []types.SiafundInput{
						{
							ParentID:         types.SiafundOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiafundOutputs: []types.SiafundOutput{
						{
							Value:   1,
							Address: unlockConditions.UnlockHash(),
						},
					},
				}
			},
		},
		{
			desc: "valid Transaction - spend multiple UTXOs",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiafundInputs: []types.SiafundElement{
						{
							ID: types.SiafundOutputID{0x01},
							SiafundOutput: types.SiafundOutput{
								Value:   1,
								Address: unlockConditions.UnlockHash(),
							},
						},
						{
							ID: types.SiafundOutputID{0x02},
							SiafundOutput: types.SiafundOutput{
								Value:   2,
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiafundInputs: []types.SiafundInput{
						{
							ParentID:         types.SiafundOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
						{
							ParentID:         types.SiafundOutputID{0x02},
							UnlockConditions: unlockConditions,
						},
					},
					SiafundOutputs: []types.SiafundOutput{
						{
							Value:   3,
							Address: unlockConditions.UnlockHash(),
						},
					},
				}
			},
		},
		{
			desc: "valid Transaction - spend a time locked UTXO as soon as possible",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.UnlockConditions{
					Timelock: ms.base.childHeight(),
					PublicKeys: []types.UnlockKey{
						key.PublicKey().UnlockKey(),
					},
					SignaturesRequired: 1,
				}

				*ts = V1TransactionSupplement{
					SiafundInputs: []types.SiafundElement{
						{
							ID: types.SiafundOutputID{0x01},
							SiafundOutput: types.SiafundOutput{
								Value:   1,
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiafundInputs: []types.SiafundInput{
						{
							ParentID:         types.SiafundOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiafundOutputs: []types.SiafundOutput{
						{
							Value: 1,
						},
					},
				}

			},
		},
		{
			desc: "valid Transaction - spend a time locked UTXO long after it unlocks",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.UnlockConditions{
					Timelock: 500000,
					PublicKeys: []types.UnlockKey{
						key.PublicKey().UnlockKey(),
					},
					SignaturesRequired: 1,
				}

				// Fake the current height
				ms.base.Index.Height = 1000000

				*ts = V1TransactionSupplement{
					SiafundInputs: []types.SiafundElement{
						{
							ID: types.SiafundOutputID{0x01},
							SiafundOutput: types.SiafundOutput{
								Value:   1,
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiafundInputs: []types.SiafundInput{
						{
							ParentID:         types.SiafundOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiafundOutputs: []types.SiafundOutput{
						{
							Value: 1,
						},
					},
				}

			},
		},
		{
			desc: "invalid Transaction - attempt to spend timelocked UTXO",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.UnlockConditions{
					Timelock: ms.base.childHeight() + 100,
					PublicKeys: []types.UnlockKey{
						key.PublicKey().UnlockKey(),
					},
					SignaturesRequired: 1,
				}

				*ts = V1TransactionSupplement{
					SiafundInputs: []types.SiafundElement{
						{
							ID: types.SiafundOutputID{0x01},
							SiafundOutput: types.SiafundOutput{
								Value:   1,
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiafundInputs: []types.SiafundInput{
						{
							ParentID:         types.SiafundOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiafundOutputs: []types.SiafundOutput{
						{
							Value: 1,
						},
					},
				}
			},
			errString: "siafund input 0 has timelocked parent",
		},
		{
			desc: "invalid Transaction - attempt to spend a previously spent UTXO",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				ms.spends[types.SiafundOutputID{0x01}] = types.TransactionID{0x00}

				*ts = V1TransactionSupplement{
					SiafundInputs: []types.SiafundElement{
						{
							ID: types.SiafundOutputID{0x01},
							SiafundOutput: types.SiafundOutput{
								Value:   1,
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiafundInputs: []types.SiafundInput{
						{
							ParentID:         types.SiafundOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiafundOutputs: []types.SiafundOutput{
						{
							Value: 1,
						},
					},
				}

			},
			errString: "siafund input 0 double-spends parent output (previously spent in 0000000000000000000000000000000000000000000000000000000000000000)",
		},
		{
			desc: "invalid Transaction - attempt to spend a nonexistent UTXO",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*txn = types.Transaction{
					SiafundInputs: []types.SiafundInput{
						{
							ParentID:         types.SiafundOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiafundOutputs: []types.SiafundOutput{
						{
							Value: 1,
						},
					},
				}

			},
			errString: "siafund input 0 spends nonexistent siafund output 0100000000000000000000000000000000000000000000000000000000000000",
		},
		{
			desc: "invalid Transaction - attempt to spend with incorrect UnlockConditions",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiafundInputs: []types.SiafundElement{
						{
							ID: types.SiafundOutputID{0x01},
							SiafundOutput: types.SiafundOutput{
								Value:   1,
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiafundInputs: []types.SiafundInput{
						{
							ParentID:         types.SiafundOutputID{0x01},
							UnlockConditions: types.UnlockConditions{},
						},
					},
					SiafundOutputs: []types.SiafundOutput{
						{
							Value: 1,
						},
					},
				}

			},
			errString: "siafund input 0 claims incorrect unlock conditions for siafund output 0100000000000000000000000000000000000000000000000000000000000000",
		},
		{
			desc: "valid Transaction - spend with incorrect UnlockConditions dev addr special case",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				// Fake the current height
				ms.base.Index.Height = ms.base.Network.HardforkDevAddr.Height

				// Set the new dev address
				ms.base.Network.HardforkDevAddr.NewAddress = unlockConditions.UnlockHash()

				*ts = V1TransactionSupplement{
					SiafundInputs: []types.SiafundElement{
						{
							ID: types.SiafundOutputID{0x01},
							SiafundOutput: types.SiafundOutput{
								Value:   1,
								Address: ms.base.Network.HardforkDevAddr.OldAddress,
							},
						},
					},
				}

				*txn = types.Transaction{
					SiafundInputs: []types.SiafundInput{
						{
							ParentID:         types.SiafundOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiafundOutputs: []types.SiafundOutput{
						{
							Value: 1,
						},
					},
				}

			},
		},
		{
			desc: "invalid Transaction - dev addr special case before hardfork height",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				ms.base.Network.HardforkDevAddr.Height = 100
				ms.base.Network.HardforkDevAddr.NewAddress = unlockConditions.UnlockHash()

				*ts = V1TransactionSupplement{
					SiafundInputs: []types.SiafundElement{
						{
							ID: types.SiafundOutputID{0x01},
							SiafundOutput: types.SiafundOutput{
								Value:   1,
								Address: ms.base.Network.HardforkDevAddr.OldAddress,
							},
						},
					},
				}

				*txn = types.Transaction{
					SiafundInputs: []types.SiafundInput{
						{
							ParentID:         types.SiafundOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiafundOutputs: []types.SiafundOutput{
						{Value: 1},
					},
				}
			},
			errString: "siafund input 0 claims incorrect unlock conditions",
		},
		{
			desc: "valid Transaction - spend a UTXO to multiple SiafundOutputs",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiafundInputs: []types.SiafundElement{
						{
							ID: types.SiafundOutputID{0x01},
							SiafundOutput: types.SiafundOutput{
								Value:   2,
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiafundInputs: []types.SiafundInput{
						{
							ParentID:         types.SiafundOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiafundOutputs: []types.SiafundOutput{
						{Value: 1},
						{Value: 1},
					},
				}

			},
		},
		{
			desc: "invalid Transaction - attempt to spend too much to SiafundOutput",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiafundInputs: []types.SiafundElement{
						{
							ID: types.SiafundOutputID{0x01},
							SiafundOutput: types.SiafundOutput{
								Value:   1,
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiafundInputs: []types.SiafundInput{
						{
							ParentID:         types.SiafundOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiafundOutputs: []types.SiafundOutput{
						{Value: 2},
					},
				}

			},
			errString: "siafund inputs (1) do not equal outputs (2)",
		},
		{
			desc: "invalid Transaction - attempt to spend too little to SiafundOutput",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiafundInputs: []types.SiafundElement{
						{
							ID: types.SiafundOutputID{0x01},
							SiafundOutput: types.SiafundOutput{
								Value:   2,
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiafundInputs: []types.SiafundInput{
						{
							ParentID:         types.SiafundOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
					SiafundOutputs: []types.SiafundOutput{
						{Value: 1},
					},
				}

			},
			errString: "siafund inputs (2) do not equal outputs (1)",
		},
		{
			desc: "invalid Transaction - attempt to spend to nothing",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				key := types.GeneratePrivateKey()
				unlockConditions := types.StandardUnlockConditions(key.PublicKey())

				*ts = V1TransactionSupplement{
					SiafundInputs: []types.SiafundElement{
						{
							ID: types.SiafundOutputID{0x01},
							SiafundOutput: types.SiafundOutput{
								Value:   1,
								Address: unlockConditions.UnlockHash(),
							},
						},
					},
				}

				*txn = types.Transaction{
					SiafundInputs: []types.SiafundInput{
						{
							ParentID:         types.SiafundOutputID{0x01},
							UnlockConditions: unlockConditions,
						},
					},
				}

			},
			errString: "siafund inputs (1) do not equal outputs (0)",
		},
	}

	for _, test := range tests {
		_, s := newConsensusDB(n, genesisBlock)
		ms := NewMidState(s)
		txn := types.Transaction{}
		ts := V1TransactionSupplement{}

		t.Run(test.desc, func(t *testing.T) {
			test.mutate(ms, &txn, &ts)

			err := validateSiafunds(ms, txn, ts)

			if test.errString == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		})
	}
}

func TestValidateArbitraryData(t *testing.T) {
	n, genesisBlock := testnet()
	n.HardforkFoundation.Height = 0 // Enable foundation validation

	tests := []struct {
		desc      string
		mutate    func(ms *MidState, txn *types.Transaction)
		errString string
	}{
		{
			desc: "valid ArbitraryData - no arbitrary data",
			mutate: func(ms *MidState, txn *types.Transaction) {
				// no mutation - empty transaction is valid
			},
		},
		{
			desc: "valid ArbitraryData - any data is valid before HardforkFoundation",
			mutate: func(ms *MidState, txn *types.Transaction) {
				ms.base.Network.HardforkFoundation.Height = 0
			},
		},
		{
			desc: "valid ArbitraryData - arbitrary data without foundation prefix",
			mutate: func(ms *MidState, txn *types.Transaction) {
				// Arbitrary data without the foundation prefix should be valid
				txn.ArbitraryData = [][]byte{
					[]byte("hello"),
					[]byte("world"),
				}
			},
		},
		{
			desc: "invalid ArbitraryData - include only foundation prefix",
			mutate: func(ms *MidState, txn *types.Transaction) {
				// Arbitrary data without the foundation prefix should be valid
				txn.ArbitraryData = [][]byte{
					types.SpecifierFoundation[:],
				}
			},
			errString: "transaction contains an improperly-encoded FoundationAddressUpdate",
		},
		{
			desc: "invalid ArbitraryData - include only foundation prefix",
			mutate: func(ms *MidState, txn *types.Transaction) {
				// Arbitrary data without the foundation prefix should be valid
				txn.ArbitraryData = [][]byte{
					types.SpecifierFoundation[:],
				}
			},
			errString: "transaction contains an improperly-encoded FoundationAddressUpdate",
		},
		{
			desc: "invalid ArbitraryData - include foundation prefix followed by garbage",
			mutate: func(ms *MidState, txn *types.Transaction) {
				// Arbitrary data without the foundation prefix should be valid
				txn.ArbitraryData = [][]byte{
					types.SpecifierFoundation[:],
				}

				txn.ArbitraryData = [][]byte{
					append(types.SpecifierFoundation[:], 0xFF, 0xFF, 0xFF),
				}
			},
			errString: "transaction contains an improperly-encoded FoundationAddressUpdate",
		},
		{
			desc: "invalid ArbitraryData - set NewPrimary to VoidAddress",
			mutate: func(ms *MidState, txn *types.Transaction) {
				key := types.GeneratePrivateKey()
				otherAddress := types.StandardUnlockConditions(key.PublicKey()).UnlockHash()

				update := types.FoundationAddressUpdate{
					NewPrimary:  types.VoidAddress,
					NewFailsafe: otherAddress,
				}

				var buf bytes.Buffer
				e := types.NewEncoder(&buf)
				types.SpecifierFoundation.EncodeTo(e)
				update.EncodeTo(e)
				e.Flush()

				txn.ArbitraryData = [][]byte{
					buf.Bytes(),
				}
			},
			errString: "transaction contains an uninitialized FoundationAddressUpdate",
		},
		{
			desc: "invalid ArbitraryData - set NewFailsafe to VoidAddress",
			mutate: func(ms *MidState, txn *types.Transaction) {
				key := types.GeneratePrivateKey()
				otherAddress := types.StandardUnlockConditions(key.PublicKey()).UnlockHash()

				update := types.FoundationAddressUpdate{
					NewPrimary:  otherAddress,
					NewFailsafe: types.VoidAddress,
				}

				var buf bytes.Buffer
				e := types.NewEncoder(&buf)
				types.SpecifierFoundation.EncodeTo(e)
				update.EncodeTo(e)
				e.Flush()

				txn.ArbitraryData = [][]byte{
					buf.Bytes(),
				}
			},
			errString: "transaction contains an uninitialized FoundationAddressUpdate",
		},
		{
			desc: "invalid Arbitrary Data - update without including signatures",
			mutate: func(ms *MidState, txn *types.Transaction) {
				key := types.GeneratePrivateKey()
				address := types.StandardUnlockConditions(key.PublicKey()).UnlockHash()

				update := types.FoundationAddressUpdate{
					NewPrimary:  address,
					NewFailsafe: address,
				}

				var buf bytes.Buffer
				e := types.NewEncoder(&buf)
				types.SpecifierFoundation.EncodeTo(e)
				update.EncodeTo(e)
				e.Flush()

				txn.ArbitraryData = [][]byte{
					buf.Bytes(),
				}
			},
			errString: "transaction contains an unsigned FoundationAddressUpdate",
		},
		{
			desc: "valid Arbitrary Data - update addresses via FoundationSubsidyAddress",
			mutate: func(ms *MidState, txn *types.Transaction) {
				key := types.GeneratePrivateKey()
				uc := types.StandardUnlockConditions(key.PublicKey())
				address := uc.UnlockHash()

				ms.base.FoundationSubsidyAddress = address

				update := types.FoundationAddressUpdate{
					NewPrimary:  address,
					NewFailsafe: address,
				}

				var buf bytes.Buffer
				e := types.NewEncoder(&buf)
				types.SpecifierFoundation.EncodeTo(e)
				update.EncodeTo(e)
				e.Flush()

				parentID := types.SiacoinOutputID{0x01}
				txn.ArbitraryData = [][]byte{
					buf.Bytes(),
				}
				txn.SiacoinInputs = []types.SiacoinInput{
					{
						ParentID:         parentID,
						UnlockConditions: uc,
					},
				}
				txn.Signatures = []types.TransactionSignature{
					{
						ParentID: types.Hash256(parentID),
						CoveredFields: types.CoveredFields{
							WholeTransaction: true,
						},
					},
				}
			},
		},
		{
			desc: "valid Arbitrary Data - update addresses via FoundationManagementAddress",
			mutate: func(ms *MidState, txn *types.Transaction) {
				key := types.GeneratePrivateKey()
				uc := types.StandardUnlockConditions(key.PublicKey())
				address := uc.UnlockHash()

				ms.base.FoundationManagementAddress = address

				update := types.FoundationAddressUpdate{
					NewPrimary:  address,
					NewFailsafe: address,
				}

				var buf bytes.Buffer
				e := types.NewEncoder(&buf)
				types.SpecifierFoundation.EncodeTo(e)
				update.EncodeTo(e)
				e.Flush()

				parentID := types.SiacoinOutputID{0x01}
				txn.ArbitraryData = [][]byte{
					buf.Bytes(),
				}
				txn.SiacoinInputs = []types.SiacoinInput{
					{
						ParentID:         parentID,
						UnlockConditions: uc,
					},
				}
				txn.Signatures = []types.TransactionSignature{
					{
						ParentID: types.Hash256(parentID),
						CoveredFields: types.CoveredFields{
							WholeTransaction: true,
						},
					},
				}
			},
		},
	}

	for _, test := range tests {
		_, s := newConsensusDB(n, genesisBlock)
		n.HardforkFoundation.Height = 0

		ms := NewMidState(s)
		txn := types.Transaction{}

		t.Run(test.desc, func(t *testing.T) {
			test.mutate(ms, &txn)
			err := validateArbitraryData(ms, txn)

			if test.errString == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		})
	}
}

func TestValidateV2Siacoins(t *testing.T) {
	n, genesisBlock := testnet()

	tests := []struct {
		desc      string
		mutate    func(ms *MidState, txn *types.V2Transaction)
		errString string
	}{
		{
			desc: "valid V2Transaction - empty",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				// no mutation
			},
		},
		{
			desc: "valid V2Transaction - spend a UTXO from the Accumulator",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				// Add a UTXO to the Accmulator
				spendTxn := types.V2Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value:   types.Siacoins(1000),
							Address: address,
						},
					},
				}
				diff := ms.createSiacoinElement(txn.SiacoinOutputID(spendTxn.ID(), 0), spendTxn.SiacoinOutputs[0])

				txn.SiacoinInputs = []types.V2SiacoinInput{
					{
						Parent: diff.SiacoinElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiacoinOutputs = []types.SiacoinOutput{
					{
						Value:   types.Siacoins(1000),
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiacoinInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
		},
		{
			desc: "valid V2Transaction - populate all Currency fields summed in outputSum and inputSum",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				// Add a UTXO to the Accmulator
				spendTxn := types.V2Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value:   types.Siacoins(11),
							Address: address,
						},
					},
				}
				diff := ms.createSiacoinElement(txn.SiacoinOutputID(spendTxn.ID(), 0), spendTxn.SiacoinOutputs[0])

				txn.SiacoinInputs = []types.V2SiacoinInput{
					{
						Parent: diff.SiacoinElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiacoinOutputs = []types.SiacoinOutput{
					{
						Value:   types.Siacoins(2),
						Address: address,
					},
					{
						Value:   types.Siacoins(2),
						Address: address,
					},
				}
				txn.FileContracts = []types.V2FileContract{
					{
						RenterOutput: types.SiacoinOutput{
							Value: types.Siacoins(2),
						},
						HostOutput: types.SiacoinOutput{
							Value: types.Siacoins(2),
						},
					},
				}
				txn.FileContractResolutions = []types.V2FileContractResolution{
					{
						Resolution: &types.V2FileContractRenewal{
							RenterRollover: types.Siacoins(1),
							HostRollover:   types.Siacoins(1),
							NewContract: types.V2FileContract{
								RenterOutput: types.SiacoinOutput{
									Value: types.Siacoins(2),
								},
								HostOutput: types.SiacoinOutput{
									Value: types.Siacoins(2),
								},
							},
						},
					},
				}
				fcOffset := ms.base.V2FileContractTax(txn.FileContracts[0])
				revOffset := ms.base.V2FileContractTax(txn.FileContractResolutions[0].Resolution.(*types.V2FileContractRenewal).NewContract)
				txn.MinerFee = types.Siacoins(1).Sub(revOffset).Sub(fcOffset)
				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiacoinInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
		},
		{
			desc: "invalid V2Transaction - double spend parent output (ephemeral)",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				parentID := types.SiacoinOutputID{0x01}

				txn.SiacoinInputs = []types.V2SiacoinInput{
					{
						Parent: types.SiacoinElement{
							ID: parentID,
						},
					},
				}

				ms.spends[parentID] = types.TransactionID{0x00}
			},
			errString: "siacoin input 0 double-spends parent output (previously spent in 0000000000000000000000000000000000000000000000000000000000000000)",
		},
		{
			desc: "invalid V2Transaction - double spend output already spent in accumulator",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				// Create a UTXO and add it to the accumulator as spent
				spendTxn := types.V2Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value:   types.Siacoins(1000),
							Address: address,
						},
					},
				}
				outputID := txn.SiacoinOutputID(spendTxn.ID(), 0)
				sce := types.SiacoinElement{
					ID:            outputID,
					SiacoinOutput: spendTxn.SiacoinOutputs[0],
				}

				// Add the element to the accumulator as spent
				leaves := []elementLeaf{siacoinLeaf(&sce, true)}
				ms.base.Elements.addLeaves(leaves)

				// Try to spend it
				txn.SiacoinInputs = []types.V2SiacoinInput{
					{
						Parent: sce,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiacoinOutputs = []types.SiacoinOutput{
					{
						Value:   types.Siacoins(1000),
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiacoinInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siacoin input 0 double-spends output",
		},
		{
			desc: "invalid V2Transaction - double spend within the same transaction",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				address := types.PolicyPublicKey(key.PublicKey()).Address()

				// Add a UTXO to the Accmulator
				spendTxn := types.V2Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value:   types.Siacoins(1000),
							Address: address,
						},
					},
				}
				diff := ms.createSiacoinElement(txn.SiacoinOutputID(spendTxn.ID(), 0), spendTxn.SiacoinOutputs[0])

				txn.SiacoinInputs = []types.V2SiacoinInput{
					{
						Parent: diff.SiacoinElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: types.PolicyPublicKey(key.PublicKey()),
						},
					},
				}

				// Double spend the same UTXO
				txn.SiacoinInputs = append(txn.SiacoinInputs, txn.SiacoinInputs[0])

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiacoinInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
				txn.SiacoinInputs[1].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siacoin input 1 double-spends parent output (previously spent by input 0)",
		},
		{
			desc: "invalid V2Transaction - spend an immature parent UTXO",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				address := types.PolicyPublicKey(key.PublicKey()).Address()

				// Add a UTXO to the Accmulator
				spendTxn := types.V2Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value:   types.Siacoins(1000),
							Address: address,
						},
					},
				}
				diff := ms.createImmatureSiacoinElement(txn.SiacoinOutputID(spendTxn.ID(), 0), spendTxn.SiacoinOutputs[0])

				txn.SiacoinInputs = []types.V2SiacoinInput{
					{
						Parent: diff.SiacoinElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: types.PolicyPublicKey(key.PublicKey()),
						},
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiacoinInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siacoin input 0 has immature parent",
		},
		{
			desc: "invalid V2Transaction - spend nonexistent ephemeral output !ok case",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()

				txn.SiacoinInputs = []types.V2SiacoinInput{
					{
						Parent: types.SiacoinElement{
							StateElement: types.StateElement{
								LeafIndex: types.UnassignedLeafIndex,
							},
						},
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: types.PolicyPublicKey(key.PublicKey()),
						},
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiacoinInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siacoin input 0 spends nonexistent ephemeral output 0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			desc: "invalid V2Transaction - spend nonexistent ephemeral output !ms.sces[i].Created case",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				address := types.PolicyPublicKey(key.PublicKey()).Address()

				// Add a UTXO to the Accmulator
				spendTxn := types.V2Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value:   types.Siacoins(1000),
							Address: address,
						},
					},
				}
				diff := ms.createSiacoinElement(txn.SiacoinOutputID(spendTxn.ID(), 0), spendTxn.SiacoinOutputs[0])

				txn.SiacoinInputs = []types.V2SiacoinInput{
					{
						Parent: types.SiacoinElement{
							StateElement: types.StateElement{
								LeafIndex: types.UnassignedLeafIndex,
							},
						},
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: types.PolicyPublicKey(key.PublicKey()),
						},
					},
				}

				ms.elements[txn.SiacoinInputs[0].Parent.ID] = 0
				ms.sces[0] = *diff
				ms.sces[0].Created = false

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiacoinInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siacoin input 0 spends nonexistent ephemeral output 0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			desc: "invalid V2Transaction - attempt to spend UTXO not in the Accumulator",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				txn.SiacoinInputs = []types.V2SiacoinInput{
					{
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiacoinOutputs = []types.SiacoinOutput{
					{
						Value:   types.Siacoins(1000),
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiacoinInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siacoin input 0 spends output (0000000000000000000000000000000000000000000000000000000000000000) not present in the accumulator",
		},
		{
			desc: "invalid V2Transaction - claim incorrect policy for parent address",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				// Add a UTXO to the Accmulator
				spendTxn := types.V2Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value:   types.Siacoins(1000),
							Address: types.VoidAddress,
						},
					},
				}
				diff := ms.createSiacoinElement(txn.SiacoinOutputID(spendTxn.ID(), 0), spendTxn.SiacoinOutputs[0])

				txn.SiacoinInputs = []types.V2SiacoinInput{
					{
						Parent: diff.SiacoinElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiacoinOutputs = []types.SiacoinOutput{
					{
						Value:   types.Siacoins(1000),
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiacoinInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siacoin input 0 claims incorrect policy for parent address",
		},
		{
			desc: "invalid V2Transaction - fail to satisfy policy",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				// Add a UTXO to the Accmulator
				spendTxn := types.V2Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value:   types.Siacoins(1000),
							Address: address,
						},
					},
				}
				diff := ms.createSiacoinElement(txn.SiacoinOutputID(spendTxn.ID(), 0), spendTxn.SiacoinOutputs[0])

				txn.SiacoinInputs = []types.V2SiacoinInput{
					{
						Parent: diff.SiacoinElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiacoinOutputs = []types.SiacoinOutput{
					{
						Value:   types.Siacoins(1000),
						Address: address,
					},
				}
			},
			errString: "siacoin input 0 failed to satisfy spend policy: invalid signature",
		},
		{
			desc: "invalid V2Transaction - include 0 value output",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				// Add a UTXO to the Accmulator
				spendTxn := types.V2Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value:   types.Siacoins(1000),
							Address: address,
						},
					},
				}
				diff := ms.createSiacoinElement(txn.SiacoinOutputID(spendTxn.ID(), 0), spendTxn.SiacoinOutputs[0])

				txn.SiacoinInputs = []types.V2SiacoinInput{
					{
						Parent: diff.SiacoinElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiacoinOutputs = []types.SiacoinOutput{
					{
						Value:   types.ZeroCurrency,
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiacoinInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siacoin output 0 has zero value",
		},
		{
			desc: "valid V2Transaction - inputs greater than outputs",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				// Add a UTXO to the Accmulator
				spendTxn := types.V2Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value:   types.Siacoins(1000),
							Address: address,
						},
					},
				}
				diff := ms.createSiacoinElement(txn.SiacoinOutputID(spendTxn.ID(), 0), spendTxn.SiacoinOutputs[0])

				txn.SiacoinInputs = []types.V2SiacoinInput{
					{
						Parent: diff.SiacoinElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiacoinOutputs = []types.SiacoinOutput{
					{
						Value:   types.Siacoins(500),
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiacoinInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siacoin inputs (1 KS) do not equal outputs (500 SC)",
		},
		{
			desc: "valid V2Transaction - inputs less than outputs",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				// Add a UTXO to the Accmulator
				spendTxn := types.V2Transaction{
					SiacoinOutputs: []types.SiacoinOutput{
						{
							Value:   types.Siacoins(1000),
							Address: address,
						},
					},
				}
				diff := ms.createSiacoinElement(txn.SiacoinOutputID(spendTxn.ID(), 0), spendTxn.SiacoinOutputs[0])

				txn.SiacoinInputs = []types.V2SiacoinInput{
					{
						Parent: diff.SiacoinElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiacoinOutputs = []types.SiacoinOutput{
					{
						Value:   types.Siacoins(2000),
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiacoinInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siacoin inputs (1 KS) do not equal outputs (2 KS)",
		},
	}

	for _, test := range tests {
		_, s := newConsensusDB(n, genesisBlock)
		ms := NewMidState(s)
		txn := types.V2Transaction{}

		t.Run(test.desc, func(t *testing.T) {
			test.mutate(ms, &txn)

			err := validateV2Siacoins(ms, txn)

			if test.errString == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		})
	}
}

func TestValidateV2Siafunds(t *testing.T) {
	n, genesisBlock := testnet()

	tests := []struct {
		desc      string
		mutate    func(ms *MidState, txn *types.V2Transaction)
		errString string
	}{
		{
			desc: "valid V2Transaction - empty",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				// no mutation
			},
		},
		{
			desc: "valid V2Transaction - spend a siafund UTXO from the Accumulator",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				// Add a siafund UTXO to the Accumulator
				spendTxn := types.V2Transaction{
					SiafundOutputs: []types.SiafundOutput{
						{
							Value:   1000,
							Address: address,
						},
					},
				}
				diff := ms.createSiafundElement(txn.SiafundOutputID(spendTxn.ID(), 0), spendTxn.SiafundOutputs[0])

				txn.SiafundInputs = []types.V2SiafundInput{
					{
						Parent: diff.SiafundElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiafundOutputs = []types.SiafundOutput{
					{
						Value:   1000,
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiafundInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
		},
		{
			desc: "invalid V2Transaction - double spend parent output (ephemeral)",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				parentID := types.SiafundOutputID{0x01}

				txn.SiafundInputs = []types.V2SiafundInput{
					{
						Parent: types.SiafundElement{
							ID: parentID,
						},
					},
				}

				ms.spends[parentID] = types.TransactionID{0x00}
			},
			errString: "siafund input 0 double-spends parent output (previously spent in 0000000000000000000000000000000000000000000000000000000000000000)",
		},
		{
			desc: "invalid V2Transaction - double spend output already spent in accumulator",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				// Create a siafund UTXO and add it to the accumulator as spent
				spendTxn := types.V2Transaction{
					SiafundOutputs: []types.SiafundOutput{
						{
							Value:   1000,
							Address: address,
						},
					},
				}
				outputID := txn.SiafundOutputID(spendTxn.ID(), 0)
				sfe := types.SiafundElement{
					ID:            outputID,
					SiafundOutput: spendTxn.SiafundOutputs[0],
				}

				// Add the element to the accumulator as spent
				leaves := []elementLeaf{siafundLeaf(&sfe, true)}
				ms.base.Elements.addLeaves(leaves)

				// Try to spend it
				txn.SiafundInputs = []types.V2SiafundInput{
					{
						Parent: sfe,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiafundOutputs = []types.SiafundOutput{
					{
						Value:   1000,
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiafundInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siafund input 0 double-spends output",
		},
		{
			desc: "invalid V2Transaction - double spend within the same transaction",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				address := types.PolicyPublicKey(key.PublicKey()).Address()

				// Add a siafund UTXO to the Accumulator
				spendTxn := types.V2Transaction{
					SiafundOutputs: []types.SiafundOutput{
						{
							Value:   1000,
							Address: address,
						},
					},
				}
				diff := ms.createSiafundElement(txn.SiafundOutputID(spendTxn.ID(), 0), spendTxn.SiafundOutputs[0])

				txn.SiafundInputs = []types.V2SiafundInput{
					{
						Parent: diff.SiafundElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: types.PolicyPublicKey(key.PublicKey()),
						},
					},
					{
						Parent: diff.SiafundElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: types.PolicyPublicKey(key.PublicKey()),
						},
					},
				}
				txn.SiafundOutputs = []types.SiafundOutput{
					{
						Value:   1000,
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiafundInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
				txn.SiafundInputs[1].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siafund input 1 double-spends parent output (previously spent by input 0)",
		},
		{
			desc: "invalid V2Transaction - spend nonexistent ephemeral output !ok case",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				address := types.PolicyPublicKey(key.PublicKey()).Address()

				txn.SiafundInputs = []types.V2SiafundInput{
					{
						Parent: types.SiafundElement{
							StateElement: types.StateElement{
								LeafIndex: types.UnassignedLeafIndex,
							},
						},
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: types.PolicyPublicKey(key.PublicKey()),
						},
					},
				}
				txn.SiafundOutputs = []types.SiafundOutput{
					{
						Value:   1000,
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiafundInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siafund input 0 spends nonexistent ephemeral output 0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			desc: "invalid V2Transaction - spend nonexistent ephemeral output !ms.sfes[i].Created case",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				address := types.PolicyPublicKey(key.PublicKey()).Address()

				// Add a siafund UTXO to the Accumulator
				spendTxn := types.V2Transaction{
					SiafundOutputs: []types.SiafundOutput{
						{
							Value:   1000,
							Address: address,
						},
					},
				}
				diff := ms.createSiafundElement(txn.SiafundOutputID(spendTxn.ID(), 0), spendTxn.SiafundOutputs[0])

				txn.SiafundInputs = []types.V2SiafundInput{
					{
						Parent: types.SiafundElement{
							StateElement: types.StateElement{
								LeafIndex: types.UnassignedLeafIndex,
							},
						},
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: types.PolicyPublicKey(key.PublicKey()),
						},
					},
				}
				txn.SiafundOutputs = []types.SiafundOutput{
					{
						Value:   1000,
						Address: address,
					},
				}

				ms.elements[txn.SiafundInputs[0].Parent.ID] = 0
				ms.sfes[0] = *diff
				ms.sfes[0].Created = false

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiafundInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siafund input 0 spends nonexistent ephemeral output 0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			desc: "invalid V2Transaction - attempt to spend UTXO not in the Accumulator",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				txn.SiafundInputs = []types.V2SiafundInput{
					{
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiafundOutputs = []types.SiafundOutput{
					{
						Value:   1000,
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiafundInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siafund input 0 spends output (0000000000000000000000000000000000000000000000000000000000000000) not present in the accumulator",
		},
		{
			desc: "invalid V2Transaction - claim incorrect policy for parent address",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				// Add a siafund UTXO to the Accumulator
				spendTxn := types.V2Transaction{
					SiafundOutputs: []types.SiafundOutput{
						{
							Value:   1000,
							Address: types.VoidAddress,
						},
					},
				}
				diff := ms.createSiafundElement(txn.SiafundOutputID(spendTxn.ID(), 0), spendTxn.SiafundOutputs[0])

				txn.SiafundInputs = []types.V2SiafundInput{
					{
						Parent: diff.SiafundElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiafundOutputs = []types.SiafundOutput{
					{
						Value:   1000,
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiafundInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siafund input 0 claims incorrect policy for parent address",
		},
		{
			desc: "invalid V2Transaction - fail to satisfy policy",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				// Add a siafund UTXO to the Accumulator
				spendTxn := types.V2Transaction{
					SiafundOutputs: []types.SiafundOutput{
						{
							Value:   1000,
							Address: address,
						},
					},
				}
				diff := ms.createSiafundElement(txn.SiafundOutputID(spendTxn.ID(), 0), spendTxn.SiafundOutputs[0])

				txn.SiafundInputs = []types.V2SiafundInput{
					{
						Parent: diff.SiafundElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiafundOutputs = []types.SiafundOutput{
					{
						Value:   1000,
						Address: address,
					},
				}
			},
			errString: "siafund input 0 failed to satisfy spend policy: invalid signature",
		},
		{
			desc: "invalid V2Transaction - include 0 value output",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				// Add a siafund UTXO to the Accumulator
				spendTxn := types.V2Transaction{
					SiafundOutputs: []types.SiafundOutput{
						{
							Value:   1000,
							Address: address,
						},
					},
				}
				diff := ms.createSiafundElement(txn.SiafundOutputID(spendTxn.ID(), 0), spendTxn.SiafundOutputs[0])

				txn.SiafundInputs = []types.V2SiafundInput{
					{
						Parent: diff.SiafundElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiafundOutputs = []types.SiafundOutput{
					{
						Value:   500,
						Address: address,
					},
					{
						Value:   0,
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiafundInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siafund output 1 has zero value",
		},
		{
			desc: "invalid V2Transaction - inputs greater than outputs",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				// Add a siafund UTXO to the Accumulator
				spendTxn := types.V2Transaction{
					SiafundOutputs: []types.SiafundOutput{
						{
							Value:   1000,
							Address: address,
						},
					},
				}
				diff := ms.createSiafundElement(txn.SiafundOutputID(spendTxn.ID(), 0), spendTxn.SiafundOutputs[0])

				txn.SiafundInputs = []types.V2SiafundInput{
					{
						Parent: diff.SiafundElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiafundOutputs = []types.SiafundOutput{
					{
						Value:   500,
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiafundInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siafund inputs (1000 SF) do not equal outputs (500 SF)",
		},
		{
			desc: "invalid V2Transaction - inputs less than outputs",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				key := types.GeneratePrivateKey()
				spendPolicy := types.PolicyPublicKey(key.PublicKey())
				address := spendPolicy.Address()

				// Add a siafund UTXO to the Accumulator
				spendTxn := types.V2Transaction{
					SiafundOutputs: []types.SiafundOutput{
						{
							Value:   1000,
							Address: address,
						},
					},
				}
				diff := ms.createSiafundElement(txn.SiafundOutputID(spendTxn.ID(), 0), spendTxn.SiafundOutputs[0])

				txn.SiafundInputs = []types.V2SiafundInput{
					{
						Parent: diff.SiafundElement,
						SatisfiedPolicy: types.SatisfiedPolicy{
							Policy: spendPolicy,
						},
					},
				}
				txn.SiafundOutputs = []types.SiafundOutput{
					{
						Value:   2000,
						Address: address,
					},
				}

				sigHash := ms.base.InputSigHash(*txn)
				sig := key.SignHash(sigHash)
				txn.SiafundInputs[0].SatisfiedPolicy.Signatures = []types.Signature{sig}
			},
			errString: "siafund inputs (1000 SF) do not equal outputs (2000 SF)",
		},
	}

	for _, test := range tests {
		_, s := newConsensusDB(n, genesisBlock)
		ms := NewMidState(s)
		txn := types.V2Transaction{}

		t.Run(test.desc, func(t *testing.T) {
			test.mutate(ms, &txn)

			err := validateV2Siafunds(ms, txn)

			if test.errString == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		})
	}
}

// This test is non-exhaustive and only focuses on missing test coverage.
// See TestValidateBlock for remaining cases
func TestValidateFileContracts(t *testing.T) {
	n, genesisBlock := testnet()
	n.HardforkTax.Height = 0
	tests := []struct {
		desc      string
		mutate    func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement)
		errString string
	}{
		{
			desc: "valid File Contract",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				// no mutation
			},
		},
		{
			desc: "invalid Storage Proof - root does not match contract Merkle root ",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				ts.StorageProofs = []V1StorageProofSupplement{
					{
						FileContract: types.FileContractElement{
							ID:           txn.FileContractID(0),
							FileContract: txn.FileContracts[0],
						},
					},
				}

				storageProof := types.StorageProof{
					ParentID: txn.FileContractID(0),
				}
				var txn2 types.Transaction
				txn2.StorageProofs = append(txn.StorageProofs, storageProof)

				*txn = txn2
			},
			errString: "storage proof 0 has root that does not match contract Merkle root",
		},
		{
			desc: "valid Storage Proof - filesize == 0 does not require a valid proof",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				ms.base.Network.HardforkTax.Height = 0
				ms.base.Network.HardforkStorageProof.Height = 0
				txn.FileContracts[0].Filesize = 0

				ts.StorageProofs = []V1StorageProofSupplement{
					{
						FileContract: types.FileContractElement{
							ID:           txn.FileContractID(0),
							FileContract: txn.FileContracts[0],
						},
					},
				}

				storageProof := types.StorageProof{
					ParentID: txn.FileContractID(0),
				}
				var txn2 types.Transaction
				txn2.StorageProofs = append(txn.StorageProofs, storageProof)

				*txn = txn2
			},
		},
		{
			desc: "valid Storage Proof - before HardforkTax.Height",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				ms.base.Network.HardforkTax.Height = 10

				leaf0Data := [64]byte{1}
				leaf1Data := [64]byte{2}

				// Hash each leaf
				hash0 := ms.base.StorageProofLeafHash(leaf0Data[:])
				hash1 := ms.base.StorageProofLeafHash(leaf1Data[:])

				// Combine to create Merkle root
				merkleRoot := blake2b.SumPair(hash0, hash1)

				txn.FileContracts[0].FileMerkleRoot = merkleRoot
				txn.FileContracts[0].WindowStart = 0
				txn.FileContracts[0].WindowEnd = 10
				txn.FileContracts[0].Filesize = 128

				ts.StorageProofs = []V1StorageProofSupplement{
					{
						FileContract: types.FileContractElement{
							ID:           txn.FileContractID(0),
							FileContract: txn.FileContracts[0],
						},
					},
				}

				leafIndex := ms.base.StorageProofLeafIndex(
					txn.FileContracts[0].Filesize,
					types.BlockID{},
					txn.FileContractID(0),
				)

				sp := types.StorageProof{
					ParentID: txn.FileContractID(0),
				}
				if leafIndex == 0 {
					// Prove leaf 0, include hash of leaf 1 as proof
					sp.Leaf = leaf0Data
					sp.Proof = []types.Hash256{hash1}
				} else {
					// Prove leaf 1, include hash of leaf 0 as proof
					sp.Leaf = leaf1Data
					sp.Proof = []types.Hash256{hash0}
				}

				var txn2 types.Transaction
				txn2.StorageProofs = append(txn.StorageProofs, sp)

				*txn = txn2
			},
		},
		{
			desc: "valid Storage Proof - after HardforkTax.Height before HardforkStorageProof.Height",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				ms.base.Network.HardforkTax.Height = 0
				ms.base.Network.HardforkStorageProof.Height = 20

				leaf0Data := [64]byte{1}
				leaf1Data := [64]byte{2}

				// Hash each leaf
				hash0 := ms.base.StorageProofLeafHash(leaf0Data[:])
				hash1 := ms.base.StorageProofLeafHash(leaf1Data[:])

				// Combine to create Merkle root
				merkleRoot := blake2b.SumPair(hash0, hash1)

				txn.FileContracts[0].FileMerkleRoot = merkleRoot
				txn.FileContracts[0].WindowStart = 0
				txn.FileContracts[0].WindowEnd = 10
				txn.FileContracts[0].Filesize = 127

				ts.StorageProofs = []V1StorageProofSupplement{
					{
						FileContract: types.FileContractElement{
							ID:           txn.FileContractID(0),
							FileContract: txn.FileContracts[0],
						},
					},
				}

				leafIndex := ms.base.StorageProofLeafIndex(
					txn.FileContracts[0].Filesize,
					types.BlockID{},
					txn.FileContractID(0),
				)

				sp := types.StorageProof{
					ParentID: txn.FileContractID(0),
				}
				if leafIndex == 0 {
					// Prove leaf 0, include hash of leaf 1 as proof
					sp.Leaf = leaf0Data
					sp.Proof = []types.Hash256{hash1}
				} else {
					// Prove leaf 1, include hash of leaf 0 as proof
					sp.Leaf = leaf1Data
					sp.Proof = []types.Hash256{hash0}
				}

				var txn2 types.Transaction
				txn2.StorageProofs = append(txn.StorageProofs, sp)

				*txn = txn2
			},
		},
		{
			desc: "valid Storage Proof - after HardforkTax.Height and HardforkStorageProof.Height",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				ms.base.Network.HardforkTax.Height = 0
				ms.base.Network.HardforkStorageProof.Height = 0

				leaf0Data := [64]byte{1}
				leaf1Data := [64]byte{2}

				// Hash each leaf
				hash0 := ms.base.StorageProofLeafHash(leaf0Data[:])
				hash1 := ms.base.StorageProofLeafHash(leaf1Data[:])

				// Combine to create Merkle root
				merkleRoot := blake2b.SumPair(hash0, hash1)

				txn.FileContracts[0].FileMerkleRoot = merkleRoot
				txn.FileContracts[0].WindowStart = 0
				txn.FileContracts[0].WindowEnd = 10
				txn.FileContracts[0].Filesize = 128

				ts.StorageProofs = []V1StorageProofSupplement{
					{
						FileContract: types.FileContractElement{
							ID:           txn.FileContractID(0),
							FileContract: txn.FileContracts[0],
						},
					},
				}

				leafIndex := ms.base.StorageProofLeafIndex(
					txn.FileContracts[0].Filesize,
					types.BlockID{},
					txn.FileContractID(0),
				)

				sp := types.StorageProof{
					ParentID: txn.FileContractID(0),
				}
				if leafIndex == 0 {
					// Prove leaf 0, include hash of leaf 1 as proof
					sp.Leaf = leaf0Data
					sp.Proof = []types.Hash256{hash1}
				} else {
					// Prove leaf 1, include hash of leaf 0 as proof
					sp.Leaf = leaf1Data
					sp.Proof = []types.Hash256{hash0}
				}

				var txn2 types.Transaction
				txn2.StorageProofs = append(txn.StorageProofs, sp)

				*txn = txn2
			},
		},
		{
			desc: "valid Storage Proof - after HardforkTax before HardforkStorageProof - last leaf trimmed",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				ms.base.Network.HardforkTax.Height = 0
				ms.base.Network.HardforkStorageProof.Height = 100

				leafData := [64]byte{1, 2, 3, 4, 5}

				// Single leaf tree: Merkle root is just the leaf hash
				merkleRoot := ms.base.StorageProofLeafHash(leafData[:])

				txn.FileContracts[0].FileMerkleRoot = merkleRoot
				txn.FileContracts[0].Filesize = 36
				txn.FileContracts[0].WindowStart = ms.base.childHeight()
				txn.FileContracts[0].WindowEnd = ms.base.childHeight() + 10

				contractID := txn.FileContractID(0)
				windowID := ms.base.Index.ID

				ts.StorageProofs = []V1StorageProofSupplement{
					{
						FileContract: types.FileContractElement{
							ID:           contractID,
							FileContract: txn.FileContracts[0],
						},
						WindowID: windowID,
					},
				}

				var sp types.StorageProof
				sp.ParentID = contractID
				sp.Leaf = leafData
				sp.Proof = []types.Hash256{}

				var txn2 types.Transaction
				txn2.StorageProofs = append(txn2.StorageProofs, sp)
				*txn = txn2
			},
		},
		{
			desc: "valid Storage Proof - after HardforkTax and HardforkStorageProof - last leaf trimmed",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				ms.base.Network.HardforkTax.Height = 0
				ms.base.Network.HardforkStorageProof.Height = 0

				leafData := [64]byte{1, 2, 3, 4, 5}

				// Single leaf tree: Merkle root is just the leaf hash
				merkleRoot := ms.base.StorageProofLeafHash(leafData[:])

				txn.FileContracts[0].FileMerkleRoot = merkleRoot
				txn.FileContracts[0].Filesize = 36
				txn.FileContracts[0].WindowStart = ms.base.childHeight()
				txn.FileContracts[0].WindowEnd = ms.base.childHeight() + 10

				contractID := txn.FileContractID(0)
				windowID := ms.base.Index.ID

				ts.StorageProofs = []V1StorageProofSupplement{
					{
						FileContract: types.FileContractElement{
							ID:           contractID,
							FileContract: txn.FileContracts[0],
						},
						WindowID: windowID,
					},
				}

				var sp types.StorageProof
				sp.ParentID = contractID
				sp.Leaf = leafData
				sp.Proof = []types.Hash256{}

				var txn2 types.Transaction
				txn2.StorageProofs = append(txn2.StorageProofs, sp)
				*txn = txn2
			},
		},
		{
			desc: "valid Storage Proof - proving left leaf to hit SumPair(root, h)",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				filesize := uint64(128)

				leaf0Data := [64]byte{1}
				leaf1Data := [64]byte{2}

				hash0 := ms.base.StorageProofLeafHash(leaf0Data[:])
				hash1 := ms.base.StorageProofLeafHash(leaf1Data[:])
				merkleRoot := blake2b.SumPair(hash0, hash1)

				txn.FileContracts[0].FileMerkleRoot = merkleRoot
				txn.FileContracts[0].Filesize = filesize
				txn.FileContracts[0].WindowStart = ms.base.childHeight()
				txn.FileContracts[0].WindowEnd = ms.base.childHeight() + 10

				// Use a known contractID that gives leafIndex=0
				contractID := types.FileContractID{0x03}

				ts.StorageProofs = []V1StorageProofSupplement{
					{
						FileContract: types.FileContractElement{
							ID:           contractID,
							FileContract: txn.FileContracts[0],
						},
					},
				}

				// Prove leaf 0
				var sp types.StorageProof
				sp.ParentID = contractID
				sp.Leaf = leaf0Data
				sp.Proof = []types.Hash256{hash1}

				var txn2 types.Transaction
				txn2.StorageProofs = append(txn2.StorageProofs, sp)
				*txn = txn2
			},
		},
	}

	for _, test := range tests {
		_, s := newConsensusDB(n, genesisBlock)
		ms := NewMidState(s)
		txn := types.Transaction{}
		ts := V1TransactionSupplement{}

		t.Run(test.desc, func(t *testing.T) {

			renterKey := types.GeneratePrivateKey()
			hostKey := types.GeneratePrivateKey()
			fc := prepareContractFormation(renterKey.PublicKey(), hostKey.PublicKey(), types.Siacoins(1), types.Siacoins(1), ms.base.Index.Height+1, 100, types.VoidAddress)
			txn.FileContracts = append(txn.FileContracts, fc)

			test.mutate(ms, &txn, &ts)
			err := validateFileContracts(ms, txn, ts)

			if test.errString == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		})
	}
}

// This test is non-exhaustive and only focuses on missing test coverage.
// See TestValidateBlock for remaining cases
func TestValidateSignatures(t *testing.T) {
	n, genesisBlock := testnet()
	n.HardforkTax.Height = 0
	tests := []struct {
		desc      string
		mutate    func(ms *MidState, txn *types.Transaction)
		errString string
	}{
		{
			desc: "valid transaction",
			mutate: func(ms *MidState, txn *types.Transaction) {
				// no mutation
			},
		},
		{
			desc: "invalid transaction - attempt to spend entropy public key",
			mutate: func(ms *MidState, txn *types.Transaction) {
				uc := types.UnlockConditions{
					PublicKeys: []types.UnlockKey{
						{
							Algorithm: types.SpecifierEntropy,
						},
					},
					SignaturesRequired: 1,
				}

				txn.SiacoinInputs = []types.SiacoinInput{
					{
						UnlockConditions: uc,
					},
				}
				txn.Signatures = []types.TransactionSignature{
					{},
				}
			},
			errString: "signature 0 uses an entropy public key",
		},
	}

	for _, test := range tests {
		_, s := newConsensusDB(n, genesisBlock)
		ms := NewMidState(s)
		txn := types.Transaction{}

		t.Run(test.desc, func(t *testing.T) {

			test.mutate(ms, &txn)
			err := validateSignatures(ms, txn)

			if test.errString == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		})
	}
}

// This test is non-exhaustive and only focuses on missing test coverage.
// See TestValidateBlock for remaining cases
func TestValidateTransaction(t *testing.T) {
	n, genesisBlock := testnet()
	n.HardforkTax.Height = 0
	tests := []struct {
		desc      string
		mutate    func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement)
		errString string
	}{
		{
			desc: "valid File Contract",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				// no mutation
			},
		},
		{
			desc: "invalid Transaction - v1 transaction after v2 hardfork",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				ms.base.Network.HardforkV2.RequireHeight = 0
			},
			errString: "v1 transactions are not allowed after v2 hardfork is complete",
		},
		{
			desc: "invalid Transaction - greater than max weight",
			mutate: func(ms *MidState, txn *types.Transaction, ts *V1TransactionSupplement) {
				ms.base.Network.HardforkV2.RequireHeight = 2

				data := make([]byte, ms.base.MaxBlockWeight())
				txn.ArbitraryData = [][]byte{data}
			},
			errString: "transaction exceeds maximum block weight (2000088 > 2000000)",
		},
	}

	for _, test := range tests {
		_, s := newConsensusDB(n, genesisBlock)
		ms := NewMidState(s)
		txn := types.Transaction{}
		ts := V1TransactionSupplement{}

		t.Run(test.desc, func(t *testing.T) {
			test.mutate(ms, &txn, &ts)
			err := ValidateTransaction(ms, txn, ts)

			if test.errString == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		})
	}
}

// This test is non-exhaustive and only focuses on missing test coverage.
// See TestValidateV2Block for remaining cases
func TestValidateV2Transaction(t *testing.T) {
	n, genesisBlock := testnet()
	n.HardforkTax.Height = 0
	tests := []struct {
		desc      string
		mutate    func(ms *MidState, txn *types.V2Transaction)
		errString string
	}{
		{
			desc: "valid V2Transaction",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				// no mutation
			},
		},
		{
			desc: "invalid Transaction - greater than max weight",
			mutate: func(ms *MidState, txn *types.V2Transaction) {
				txn.ArbitraryData = make([]byte, ms.base.MaxBlockWeight()+1)
			},
			errString: "transaction exceeds maximum block weight (2000001 > 2000000)",
		},
	}

	for _, test := range tests {
		_, s := newConsensusDB(n, genesisBlock)
		ms := NewMidState(s)
		ms.base.Network.HardforkV2.AllowHeight = 0

		txn := types.V2Transaction{
			ArbitraryData: []byte("foo"),
		}

		t.Run(test.desc, func(t *testing.T) {
			test.mutate(ms, &txn)
			err := ValidateV2Transaction(ms, txn)

			if test.errString == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.errString) {
				t.Fatalf("expected error containing %q, got %v", test.errString, err)
			}
		})
	}
}

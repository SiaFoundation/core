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

	"go.sia.tech/core/internal/blake2b"
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
	n.HardforkFoundation.Height = 7
	n.HardforkFoundation.PrimaryAddress = types.AnyoneCanSpend().Address()
	n.HardforkFoundation.FailsafeAddress = types.VoidAddress
	n.HardforkV2.AllowHeight = 1000
	n.HardforkV2.RequireHeight = 2000
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
		db.sces[id] = sce
	}
	for id, sfe := range db.sfes {
		au.UpdateElementProof(&sfe.StateElement)
		db.sfes[id] = sfe
	}
	for id, fce := range db.fces {
		au.UpdateElementProof(&fce.StateElement)
		db.fces[id] = fce
	}
	for id, fce := range db.v2fces {
		au.UpdateElementProof(&fce.StateElement)
		db.v2fces[id] = fce
	}
	au.ForEachSiacoinElement(func(sce types.SiacoinElement, created, spent bool) {
		if spent {
			delete(db.sces, types.SiacoinOutputID(sce.ID))
		} else {
			db.sces[types.SiacoinOutputID(sce.ID)] = sce
		}
	})
	au.ForEachSiafundElement(func(sfe types.SiafundElement, created, spent bool) {
		if spent {
			delete(db.sfes, types.SiafundOutputID(sfe.ID))
		} else {
			db.sfes[types.SiafundOutputID(sfe.ID)] = sfe
		}
	})
	au.ForEachFileContractElement(func(fce types.FileContractElement, created bool, rev *types.FileContractElement, resolved, valid bool) {
		if created {
			db.fces[types.FileContractID(fce.ID)] = fce
		} else if rev != nil {
			db.fces[types.FileContractID(fce.ID)] = *rev
		} else if resolved {
			delete(db.fces, types.FileContractID(fce.ID))
		}
	})
	au.ForEachV2FileContractElement(func(fce types.V2FileContractElement, created bool, rev *types.V2FileContractElement, res types.V2FileContractResolutionType) {
		if created {
			db.v2fces[types.FileContractID(fce.ID)] = fce
		} else if rev != nil {
			db.v2fces[types.FileContractID(fce.ID)] = *rev
		} else if res != nil {
			delete(db.v2fces, types.FileContractID(fce.ID))
		}
	})
	db.blockIDs = append(db.blockIDs, au.ms.cie.ID)
}

func (db *consensusDB) revertBlock(ru RevertUpdate) {
	ru.ForEachSiacoinElement(func(sce types.SiacoinElement, created, spent bool) {
		if spent {
			db.sces[types.SiacoinOutputID(sce.ID)] = sce
		} else {
			delete(db.sces, types.SiacoinOutputID(sce.ID))
		}
	})
	ru.ForEachSiafundElement(func(sfe types.SiafundElement, created, spent bool) {
		if spent {
			db.sfes[types.SiafundOutputID(sfe.ID)] = sfe
		} else {
			delete(db.sfes, types.SiafundOutputID(sfe.ID))
		}
	})
	ru.ForEachFileContractElement(func(fce types.FileContractElement, created bool, rev *types.FileContractElement, resolved, valid bool) {
		if created {
			delete(db.fces, types.FileContractID(fce.ID))
		} else if rev != nil {
			db.fces[types.FileContractID(fce.ID)] = fce
		} else if resolved {
			db.fces[types.FileContractID(fce.ID)] = fce
		}
	})
	ru.ForEachV2FileContractElement(func(fce types.V2FileContractElement, created bool, rev *types.V2FileContractElement, res types.V2FileContractResolutionType) {
		if created {
			delete(db.v2fces, types.FileContractID(fce.ID))
		} else if rev != nil {
			db.v2fces[types.FileContractID(fce.ID)] = fce
		} else if res != nil {
			db.v2fces[types.FileContractID(fce.ID)] = fce
		}
	})
	for id, sce := range db.sces {
		ru.UpdateElementProof(&sce.StateElement)
		db.sces[id] = sce
	}
	for id, sfe := range db.sfes {
		ru.UpdateElementProof(&sfe.StateElement)
		db.sfes[id] = sfe
	}
	for id, fce := range db.fces {
		ru.UpdateElementProof(&fce.StateElement)
		db.fces[id] = fce
	}
	for id, fce := range db.v2fces {
		ru.UpdateElementProof(&fce.StateElement)
		db.v2fces[id] = fce
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
				ts.SiacoinInputs = append(ts.SiacoinInputs, sce)
			}
		}
		for _, sfi := range txn.SiafundInputs {
			if sfe, ok := db.sfes[sfi.ParentID]; ok {
				ts.SiafundInputs = append(ts.SiafundInputs, sfe)
			}
		}
		for _, fcr := range txn.FileContractRevisions {
			if fce, ok := db.fces[fcr.ParentID]; ok {
				ts.RevisedFileContracts = append(ts.RevisedFileContracts, fce)
			}
		}
		for _, sp := range txn.StorageProofs {
			if fce, ok := db.fces[sp.ParentID]; ok {
				ts.StorageProofs = append(ts.StorageProofs, V1StorageProofSupplement{
					FileContract: fce,
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
	for b.ID().CmpWork(cs.ChildTarget) < 0 {
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
					{Value: giftAmountSC.Sub(fc.Payout), Address: giftAddress},
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
			},
		},
		MinerPayouts: []types.SiacoinOutput{{
			Address: types.VoidAddress,
			Value:   cs.BlockReward(),
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
				"miner payout sum (0 SC) does not match block reward + fees (300 KS)",
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
				"miner payout sum (150 KS) does not match block reward + fees (300 KS)",
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
	var sces []types.SiacoinElement
	au.ForEachSiacoinElement(func(sce types.SiacoinElement, created, spent bool) {
		sces = append(sces, sce)
	})
	var sfes []types.SiafundElement
	au.ForEachSiafundElement(func(sfe types.SiafundElement, created, spent bool) {
		sfes = append(sfes, sfe)
	})
	var fces []types.V2FileContractElement
	au.ForEachV2FileContractElement(func(fce types.V2FileContractElement, created bool, rev *types.V2FileContractElement, res types.V2FileContractResolutionType) {
		fces = append(fces, fce)
	})
	var cies []types.ChainIndexElement
	cies = append(cies, au.ChainIndexElement())

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
					Parent:          sces[0],
					SatisfiedPolicy: types.SatisfiedPolicy{Policy: giftPolicy},
				}},
				SiafundInputs: []types.V2SiafundInput{{
					Parent:          sfes[0],
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
					{Parent: fces[0], Revision: rev1},
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
	b.V2.Commitment = cs.Commitment(cs.TransactionsCommitment(b.Transactions, b.V2Transactions()), b.MinerPayouts[0].Address)
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
				"v1 transactions are not allowed after v2 hardfork",
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
				fmt.Sprintf("file contract revision 1 parent (%v) has already been revised", fces[0].ID),
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
						Parent:     fces[0],
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
				corruptBlock.V2.Commitment = cs.Commitment(cs.TransactionsCommitment(corruptBlock.Transactions, corruptBlock.V2Transactions()), corruptBlock.MinerPayouts[0].Address)
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

	var testSces []types.SiacoinElement
	testAU.ForEachSiacoinElement(func(sce types.SiacoinElement, created, spent bool) {
		testSces = append(testSces, sce)
	})
	var testSfes []types.SiafundElement
	testAU.ForEachSiafundElement(func(sfe types.SiafundElement, created, spent bool) {
		testSfes = append(testSfes, sfe)
	})
	var testFces []types.V2FileContractElement
	testAU.ForEachV2FileContractElement(func(fce types.V2FileContractElement, created bool, rev *types.V2FileContractElement, res types.V2FileContractResolutionType) {
		testFces = append(testFces, fce)
	})
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
		b.V2.Commitment = cs.Commitment(cs.TransactionsCommitment(b.Transactions, b.V2Transactions()), b.MinerPayouts[0].Address)

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
						Parent: testFces[0],
						Resolution: &types.V2StorageProof{
							ProofIndex: cies[len(cies)-2],
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
			ProofIndex: cies[len(cies)-2],
			Leaf:       [64]byte{2},
			Proof:      []types.Hash256{cs.StorageProofLeafHash([]byte{1})},
		}
	}

	signTxn(cs, &b.V2.Transactions[0])
	b.V2.Commitment = cs.Commitment(cs.TransactionsCommitment(b.Transactions, b.V2Transactions()), b.MinerPayouts[0].Address)
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
						Parent:          testSces[0],
						SatisfiedPolicy: types.SatisfiedPolicy{Policy: giftPolicy},
					})
				},
			},
			{
				"double spend of non-parent siafund output",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiafundInputs = append(txn.SiafundInputs, types.V2SiafundInput{
						Parent:          testSfes[0],
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
						Parent:   testFces[0],
						Revision: rev,
					}}
				},
			},
			{
				"storage proof expiration at wrong proof height",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContractResolutions = []types.V2FileContractResolution{{
						Parent: testFces[0],
						Resolution: &types.V2StorageProof{
							ProofIndex: cies[len(cies)-1],
						},
					}}
				},
			},
			{
				"file contract expiration submitted before expiration height",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContractResolutions = []types.V2FileContractResolution{{
						Parent:     testFces[0],
						Resolution: &types.V2FileContractExpiration{},
					}}
				},
			},
			{
				"file contract renewal with invalid final revision",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinInputs = []types.V2SiacoinInput{{
						Parent:          sces[1],
						SatisfiedPolicy: types.SatisfiedPolicy{Policy: giftPolicy},
					}}

					resolution := types.V2FileContractRenewal{
						FinalRenterOutput: types.SiacoinOutput{Value: types.Siacoins(1e6)},
						NewContract:       testFces[0].V2FileContract,
					}
					txn.FileContractResolutions = []types.V2FileContractResolution{{
						Parent:     testFces[0],
						Resolution: &resolution,
					}}
				},
			},
			{
				"file contract renewal with invalid initial revision",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinInputs = []types.V2SiacoinInput{{
						Parent:          sces[1],
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
						Parent:     testFces[0],
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
				corruptBlock.V2.Commitment = cs.Commitment(cs.TransactionsCommitment(corruptBlock.Transactions, corruptBlock.V2Transactions()), corruptBlock.MinerPayouts[0].Address)
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
			b.V2.Commitment = cs.Commitment(cs.TransactionsCommitment(b.Transactions, b.V2Transactions()), minerAddr)
		}

		findBlockNonce(cs, &b)
		if err := ValidateBlock(cs, b, db.supplementTipBlock(b)); err != nil {
			return err
		}

		var cau ApplyUpdate
		cs, cau = ApplyBlock(cs, b, db.supplementTipBlock(b), db.ancestorTimestamp(b.ParentID))
		checkApplyUpdate(t, cs, cau)
		cau.ForEachSiacoinElement(func(sce types.SiacoinElement, created, spent bool) {
			if spent {
				delete(utxos, types.SiacoinOutputID(sce.ID))
			} else if sce.SiacoinOutput.Address == addr {
				utxos[types.SiacoinOutputID(sce.ID)] = sce
			}
		})

		for id, sce := range utxos {
			cau.UpdateElementProof(&sce.StateElement)
			utxos[id] = sce
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
			{
				Parent: sce,
			},
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
		au.ForEachV2FileContractElement(func(fce types.V2FileContractElement, created bool, rev *types.V2FileContractElement, res types.V2FileContractResolutionType) {
			switch {
			case res != nil:
				delete(fces, fce.ID)
			case rev != nil:
				fces[fce.ID] = *rev
			default:
				fces[fce.ID] = fce
			}
		})

		// update proofs
		for key, fce := range fces {
			au.UpdateElementProof(&fce.StateElement)
			fces[key] = fce
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
			{Parent: fces[contractID], Revision: rev1},
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
			{Parent: fces[contractID], Revision: rev2},
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
		au.ForEachV2FileContractElement(func(fce types.V2FileContractElement, created bool, rev *types.V2FileContractElement, res types.V2FileContractResolutionType) {
			switch {
			case res != nil:
				delete(fces, fce.ID)
			case rev != nil:
				fces[fce.ID] = *rev
			default:
				fces[fce.ID] = fce
			}
		})

		au.ForEachSiacoinElement(func(sce types.SiacoinElement, created, spent bool) {
			if sce.ID == genesisOutput.ID {
				genesisOutput = sce
			}
		})

		// update proofs
		au.UpdateElementProof(&genesisOutput.StateElement)
		for key, fce := range fces {
			au.UpdateElementProof(&fce.StateElement)
			fces[key] = fce
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
					Parent: fces[contractID],
					Resolution: &types.V2FileContractRenewal{
						FinalRenterOutput: types.SiacoinOutput{Address: fc.RenterOutput.Address, Value: types.ZeroCurrency},
						FinalHostOutput:   types.SiacoinOutput{Address: fc.HostOutput.Address, Value: types.ZeroCurrency},
						NewContract:       newContract,
						RenterRollover:    types.Siacoins(10),
						HostRollover:      types.Siacoins(10),
					},
				}},
				SiacoinInputs: []types.V2SiacoinInput{{
					Parent: genesisOutput,
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

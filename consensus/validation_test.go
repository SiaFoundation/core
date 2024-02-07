package consensus

import (
	"bytes"
	"errors"
	"math"
	"math/bits"
	"testing"
	"time"

	"go.sia.tech/core/types"
)

func testnet() (*Network, types.Block) {
	n := &Network{
		Name:            "testnet",
		InitialCoinbase: types.Siacoins(300000),
		MinimumCoinbase: types.Siacoins(300000),
		InitialTarget:   types.BlockID{0xFF},
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
	sces map[types.SiacoinOutputID]types.SiacoinElement
	sfes map[types.SiafundOutputID]types.SiafundElement
	fces map[types.FileContractID]types.FileContractElement
}

func (db *consensusDB) applyBlock(au ApplyUpdate) {
	au.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
		if spent {
			delete(db.sces, types.SiacoinOutputID(sce.ID))
		} else {
			db.sces[types.SiacoinOutputID(sce.ID)] = sce
		}
	})
	au.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
		if spent {
			delete(db.sfes, types.SiafundOutputID(sfe.ID))
		} else {
			db.sfes[types.SiafundOutputID(sfe.ID)] = sfe
		}
	})
	au.ForEachFileContractElement(func(fce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool) {
		if resolved {
			delete(db.fces, types.FileContractID(fce.ID))
		} else {
			db.fces[types.FileContractID(fce.ID)] = fce
		}
	})
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
	}
	return bs
}

func (db *consensusDB) ancestorTimestamp(id types.BlockID) time.Time {
	return time.Time{}
}

func newConsensusDB(n *Network, genesisBlock types.Block) (*consensusDB, State) {
	db := &consensusDB{
		sces: make(map[types.SiacoinOutputID]types.SiacoinElement),
		sfes: make(map[types.SiafundOutputID]types.SiafundElement),
		fces: make(map[types.FileContractID]types.FileContractElement),
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
		UnlockHash:     types.Hash256(uc.UnlockHash()),
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
		Transactions: []types.Transaction{{
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
		}},
		MinerPayouts: []types.SiacoinOutput{{
			Address: types.VoidAddress,
			Value:   cs.BlockReward(),
		}},
	}

	// block should be valid
	validBlock := deepCopyBlock(b)
	signTxn(&validBlock.Transactions[0])
	findBlockNonce(cs, &validBlock)
	if err := ValidateBlock(cs, validBlock, db.supplementTipBlock(validBlock)); err != nil {
		t.Fatal(err)
	}

	// tests with correct signatures
	{
		tests := []struct {
			desc    string
			corrupt func(*types.Block)
		}{
			{
				"weight that exceeds the limit",
				func(b *types.Block) {
					data := make([]byte, cs.MaxBlockWeight())
					b.Transactions = append(b.Transactions, types.Transaction{
						ArbitraryData: [][]byte{data},
					})
				},
			},
			{
				"wrong parent ID",
				func(b *types.Block) {
					b.ParentID[0] ^= 255
				},
			},
			{
				"wrong timestamp",
				func(b *types.Block) {
					b.Timestamp = cs.PrevTimestamps[0].AddDate(-1, 0, 0)
				},
			},
			{
				"no miner payout",
				func(b *types.Block) {
					b.MinerPayouts = nil
				},
			},
			{
				"zero miner payout",
				func(b *types.Block) {
					b.MinerPayouts = []types.SiacoinOutput{{
						Address: types.VoidAddress,
						Value:   types.ZeroCurrency,
					}}
				},
			},
			{
				"incorrect miner payout",
				func(b *types.Block) {
					b.MinerPayouts = []types.SiacoinOutput{{
						Address: types.VoidAddress,
						Value:   cs.BlockReward().Div64(2),
					}}
				},
			},
			{
				"overflowing miner payout",
				func(b *types.Block) {
					b.MinerPayouts = []types.SiacoinOutput{
						{Address: types.VoidAddress, Value: types.MaxCurrency},
						{Address: types.VoidAddress, Value: types.MaxCurrency},
					}
				},
			},
			{
				"overflowing siacoin outputs",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiacoinOutputs = []types.SiacoinOutput{
						{Address: types.VoidAddress, Value: types.MaxCurrency},
						{Address: types.VoidAddress, Value: types.MaxCurrency},
					}
				},
			},
			{
				"zero-valued SiacoinOutput",
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
				"zero-valued SiafundOutput",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					for i := range txn.SiafundOutputs {
						txn.SiafundOutputs[i].Value = 0
					}
					txn.SiafundInputs = nil
				},
			},
			{
				"zero-valued MinerFee",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.MinerFees = append(txn.MinerFees, types.ZeroCurrency)
				},
			},
			{
				"overflowing MinerFees",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.MinerFees = append(txn.MinerFees, types.MaxCurrency)
					txn.MinerFees = append(txn.MinerFees, types.MaxCurrency)
				},
			},
			{
				"siacoin outputs exceed inputs",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Add(types.NewCurrency64(1))
				},
			},
			{
				"siacoin outputs less than inputs",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Sub(types.NewCurrency64(1))
				},
			},
			{
				"siafund outputs exceed inputs",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiafundOutputs[0].Value = txn.SiafundOutputs[0].Value + 1
				},
			},
			{
				"siafund outputs less than inputs",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiafundOutputs[0].Value = txn.SiafundOutputs[0].Value - 1
				},
			},
			{
				"two of the same siacoin input",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiacoinInputs = append(txn.SiacoinInputs, txn.SiacoinInputs[0])
				},
			},
			{
				"two of the same siafund input",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiafundInputs = append(txn.SiafundInputs, txn.SiafundInputs[0])
				},
			},
			{
				"siacoin input claiming incorrect unlock conditions",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiacoinInputs[0].UnlockConditions.PublicKeys[0].Key[0] ^= 255
				},
			},
			{
				"siafund input claiming incorrect unlock conditions",
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
				"window that starts in the past",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContracts[0].WindowStart = 0
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
				"incorrect payout tax",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Add(types.Siacoins(1))
					txn.FileContracts[0].Payout = txn.FileContracts[0].Payout.Sub(types.Siacoins(1))
				},
			},
			{
				"file contract that ends after v2 hardfork",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContracts[0].WindowStart = n.HardforkV2.RequireHeight
					txn.FileContracts[0].WindowEnd = txn.FileContracts[0].WindowStart + 100
				},
			},
			{
				"revision of nonexistent file contract",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContractRevisions[0].ParentID[0] ^= 255
				},
			},
			{
				"revision with window that starts in past",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContractRevisions[0].WindowStart = cs.Index.Height
				},
			},
			{
				"revision with window that ends before it begins",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContractRevisions[0].WindowStart = txn.FileContractRevisions[0].WindowEnd
				},
			},
			{
				"revision with lower revision number than its parent",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContractRevisions[0].RevisionNumber = 0
				},
			},
			{
				"revision claiming incorrect unlock conditions",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContractRevisions[0].UnlockConditions.PublicKeys[0].Key[0] ^= 255
				},
			},
			{
				"revision having different valid payout sum",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContractRevisions[0].ValidProofOutputs = append(txn.FileContractRevisions[0].ValidProofOutputs, types.SiacoinOutput{
						Value: types.Siacoins(1),
					})
				},
			},
			{
				"revision having different missed payout sum",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.FileContractRevisions[0].MissedProofOutputs = append(txn.FileContractRevisions[0].MissedProofOutputs, types.SiacoinOutput{
						Value: types.Siacoins(1),
					})
				},
			},
			{
				"conflicting revisions in same transaction",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					newRevision := txn.FileContractRevisions[0]
					newRevision.RevisionNumber++
					txn.FileContractRevisions = append(txn.FileContractRevisions, newRevision)
				},
			},
			{
				"double-spent siacoin input",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiacoinInputs = append(txn.SiacoinInputs, txn.SiacoinInputs[0])
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Add(types.Siacoins(100))
				},
			},
			{
				"double-spent siafund input",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.SiafundInputs = append(txn.SiafundInputs, txn.SiafundInputs[0])
					txn.SiafundOutputs[0].Value = txn.SiafundOutputs[0].Value + 100
				},
			},
			{
				"transaction contains a storage proof and creates new outputs",
				func(b *types.Block) {
					txn := &b.Transactions[0]
					txn.StorageProofs = append(txn.StorageProofs, types.StorageProof{})
				},
			},
		}
		for _, test := range tests {
			corruptBlock := deepCopyBlock(validBlock)
			test.corrupt(&corruptBlock)
			signTxn(&corruptBlock.Transactions[0])
			findBlockNonce(cs, &corruptBlock)

			if err := ValidateBlock(cs, corruptBlock, db.supplementTipBlock(corruptBlock)); err == nil {
				t.Fatalf("accepted block with %v", test.desc)
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
			test.corrupt(&corruptBlock)
			findBlockNonce(cs, &corruptBlock)

			if err := ValidateBlock(cs, corruptBlock, db.supplementTipBlock(corruptBlock)); err == nil {
				t.Fatalf("accepted block with %v", test.desc)
			}
		}
	}
}

func updateProofs(au ApplyUpdate, sces []types.SiacoinElement, sfes []types.SiafundElement, fces []types.V2FileContractElement) {
	for i := range sces {
		au.UpdateElementProof(&sces[i].StateElement)
	}
	for i := range sfes {
		au.UpdateElementProof(&sfes[i].StateElement)
	}
	for i := range fces {
		au.UpdateElementProof(&fces[i].StateElement)
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
			switch r := txn.FileContractResolutions[i].Resolution.(type) {
			case *types.V2FileContractRenewal:
				r.RenterSignature = renterPrivateKey.SignHash(cs.RenewalSigHash(*r))
				r.HostSignature = hostPrivateKey.SignHash(cs.RenewalSigHash(*r))
			case *types.V2FileContractFinalization:
				r.RenterSignature = renterPrivateKey.SignHash(cs.ContractSigHash(types.V2FileContract(*r)))
				r.HostSignature = hostPrivateKey.SignHash(cs.ContractSigHash(types.V2FileContract(*r)))
			}
		}
	}

	giftAmountSC := types.Siacoins(100)
	giftAmountSF := uint64(100)
	v1GiftFC := prepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), 100, 100, types.VoidAddress)
	v2GiftFC := types.V2FileContract{
		Filesize:         v1GiftFC.Filesize,
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
	var sces []types.SiacoinElement
	au.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
		sces = append(sces, sce)
	})
	var sfes []types.SiafundElement
	au.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
		sfes = append(sfes, sfe)
	})
	var fces []types.V2FileContractElement
	au.ForEachV2FileContractElement(func(fce types.V2FileContractElement, rev *types.V2FileContractElement, res types.V2FileContractResolutionType) {
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
			desc    string
			corrupt func(*types.Block)
		}{
			{
				"v1 transaction after v2 hardfork",
				func(b *types.Block) {
					b.Transactions = []types.Transaction{{}}
				},
			},
			{
				"block height that does not increment parent height",
				func(b *types.Block) {
					b.V2.Height = 0
				},
			},
			{
				"weight that exceeds the limit",
				func(b *types.Block) {
					data := make([]byte, cs.MaxBlockWeight())
					b.V2.Transactions = append(b.V2.Transactions, types.V2Transaction{
						ArbitraryData: data,
					})
				},
			},
			{
				"wrong parent ID",
				func(b *types.Block) {
					b.ParentID[0] ^= 255
				},
			},
			{
				"wrong timestamp",
				func(b *types.Block) {
					b.Timestamp = cs.PrevTimestamps[0].AddDate(-1, 0, 0)
				},
			},
			{
				"no miner payout",
				func(b *types.Block) {
					b.MinerPayouts = nil
				},
			},
			{
				"zero miner payout",
				func(b *types.Block) {
					b.MinerPayouts = []types.SiacoinOutput{{
						Address: types.VoidAddress,
						Value:   types.ZeroCurrency,
					}}
				},
			},
			{
				"incorrect miner payout",
				func(b *types.Block) {
					b.MinerPayouts = []types.SiacoinOutput{{
						Address: types.VoidAddress,
						Value:   cs.BlockReward().Div64(2),
					}}
				},
			},
			{
				"zero-valued SiacoinOutput",
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
				"zero-valued SiafundOutput",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					for i := range txn.SiafundOutputs {
						txn.SiafundOutputs[i].Value = 0
					}
					txn.SiafundInputs = nil
				},
			},
			{
				"zero-valued MinerFee",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.MinerFee = types.ZeroCurrency
				},
			},
			{
				"overflowing MinerFees",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.MinerFee = types.MaxCurrency
				},
			},
			{
				"siacoin outputs exceed inputs",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Add(types.NewCurrency64(1))
				},
			},
			{
				"siacoin outputs less than inputs",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Sub(types.NewCurrency64(1))
				},
			},
			{
				"siafund outputs exceed inputs",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiafundOutputs[0].Value = txn.SiafundOutputs[0].Value + 1
				},
			},
			{
				"siafund outputs less than inputs",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiafundOutputs[0].Value = txn.SiafundOutputs[0].Value - 1
				},
			},
			{
				"two of the same siacoin input",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinInputs = append(txn.SiacoinInputs, txn.SiacoinInputs[0])
				},
			},
			{
				"two of the same siafund input",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiafundInputs = append(txn.SiafundInputs, txn.SiafundInputs[0])
				},
			},
			{
				"siacoin input claiming incorrect policy",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinInputs[0].SatisfiedPolicy.Policy = types.AnyoneCanSpend()
				},
			},
			{
				"siafund input claiming incorrect policy",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiafundInputs[0].SatisfiedPolicy.Policy = types.AnyoneCanSpend()
				},
			},
			{
				"invalid FoundationAddressUpdate",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					addr := types.VoidAddress
					txn.NewFoundationAddress = &addr
				},
			},
			{
				"revision that resolves contract",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContractRevisions[0].Revision.RevisionNumber = types.MaxRevisionNumber
				},
			},
			{
				"revision with window that starts in past",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContractRevisions[0].Revision.ProofHeight = cs.Index.Height
				},
			},
			{
				"revision with window that ends before it begins",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContractRevisions[0].Revision.ExpirationHeight = txn.FileContractRevisions[0].Revision.ProofHeight
				},
			},
			{
				"revision with lower revision number than its parent",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContractRevisions[0].Revision.RevisionNumber = 0
				},
			},
			{
				"revision having different valid payout sum",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContractRevisions[0].Revision.HostOutput.Value = txn.FileContractRevisions[0].Revision.HostOutput.Value.Add(types.Siacoins(1))
				},
			},
			{
				"conflicting revisions in same transaction",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					newRevision := txn.FileContractRevisions[0]
					newRevision.Revision.RevisionNumber++
					txn.FileContractRevisions = append(txn.FileContractRevisions, newRevision)
				},
			},
			{
				"window that starts in the past",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContracts[0].ProofHeight = 0
				},
			},
			{
				"window that ends before it begins",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContracts[0].ProofHeight = txn.FileContracts[0].ExpirationHeight
				},
			},
			{
				"valid payout that does not equal missed payout",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContracts[0].HostOutput.Value = txn.FileContracts[0].HostOutput.Value.Add(types.Siacoins(1))
				},
			},
			{
				"incorrect payout tax",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Add(types.Siacoins(1))
					txn.FileContracts[0].TotalCollateral = txn.FileContracts[0].TotalCollateral.Sub(types.Siacoins(1))
				},
			},
			{
				"missed host value exceeding valid host value",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContracts[0].MissedHostValue = txn.FileContracts[0].HostOutput.Value.Add(types.Siacoins(1))
				},
			},
			{
				"total collateral exceeding valid host value",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContracts[0].TotalCollateral = txn.FileContracts[0].HostOutput.Value.Add(types.Siacoins(1))
				},
			},
			{
				"spends siacoin output not in accumulator",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinInputs[0].Parent.StateElement.ID[0] ^= 255
				},
			},
			{
				"spends siafund output not in accumulator",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiafundInputs[0].Parent.StateElement.ID[0] ^= 255
				},
			},
			{
				"superfluous siacoin spend policy preimage(s)",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinInputs[0].SatisfiedPolicy.Preimages = [][]byte{{1}}
				},
			},
			{
				"superfluous siafund spend policy preimage(s)",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiafundInputs[0].SatisfiedPolicy.Preimages = [][]byte{{1}}
				},
			},
			{
				"transaction both resolves a file contract and creates new outputs",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.FileContractResolutions = append(txn.FileContractResolutions, types.V2FileContractResolution{
						Parent:     fces[0],
						Resolution: &types.V2FileContractExpiration{},
					})
				},
			},
			{
				"attestation with an empty key",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.Attestations = append(txn.Attestations, types.Attestation{})
				},
			},
			{
				"attestation with invalid signature",
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

			if err := ValidateBlock(cs, corruptBlock, db.supplementTipBlock(corruptBlock)); err == nil {
				t.Fatalf("accepted block with %v", test.desc)
			}
		}
	}

	cs, testAU := ApplyBlock(cs, validBlock, db.supplementTipBlock(validBlock), time.Now())
	db.applyBlock(testAU)
	updateProofs(testAU, sces, sfes, fces)

	var testSces []types.SiacoinElement
	testAU.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
		testSces = append(testSces, sce)
	})
	var testSfes []types.SiafundElement
	testAU.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
		testSfes = append(testSfes, sfe)
	})
	var testFces []types.V2FileContractElement
	testAU.ForEachV2FileContractElement(func(fce types.V2FileContractElement, rev *types.V2FileContractElement, res types.V2FileContractResolutionType) {
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
		db.applyBlock(au)
		updateProofs(au, sces, sfes, fces)
		updateProofs(au, testSces, testSfes, testFces)
		cies = append(cies, au.ChainIndexElement())

		blockID = b.ID()
	}

	b = types.Block{
		ParentID:  blockID,
		Timestamp: types.CurrentTimestamp(),
		V2: &types.V2BlockData{
			Height: cs.Index.Height + 1,
			Transactions: []types.V2Transaction{
				{},
			},
		},
		MinerPayouts: []types.SiacoinOutput{{
			Address: types.VoidAddress,
			Value:   cs.BlockReward(),
		}},
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
				"file contract finalization that does not set maximum revision number",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]

					resolution := types.V2FileContractFinalization(testFces[0].V2FileContract)
					txn.FileContractResolutions = []types.V2FileContractResolution{{
						Parent:     testFces[0],
						Resolution: &resolution,
					}}
				},
			},
			{
				"file contract finalization with invalid revision",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]

					resolution := types.V2FileContractFinalization(testFces[0].V2FileContract)
					resolution.RevisionNumber = types.MaxRevisionNumber
					resolution.TotalCollateral = types.ZeroCurrency
					txn.FileContractResolutions = []types.V2FileContractResolution{{
						Parent:     testFces[0],
						Resolution: &resolution,
					}}
				},
			},
			{
				"file contract renewal that does not finalize old contract",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.SiacoinInputs = []types.V2SiacoinInput{{
						Parent:          sces[1],
						SatisfiedPolicy: types.SatisfiedPolicy{Policy: giftPolicy},
					}}

					rev := testFces[0].V2FileContract
					resolution := types.V2FileContractRenewal{
						FinalRevision: rev,
						NewContract:   testFces[0].V2FileContract,
					}
					txn.FileContractResolutions = []types.V2FileContractResolution{{
						Parent:     testFces[0],
						Resolution: &resolution,
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

					rev := testFces[0].V2FileContract
					rev.RevisionNumber = types.MaxRevisionNumber
					rev.TotalCollateral = types.ZeroCurrency
					resolution := types.V2FileContractRenewal{
						FinalRevision: rev,
						NewContract:   testFces[0].V2FileContract,
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
					finalRev := testFces[0].V2FileContract
					finalRev.RevisionNumber = types.MaxRevisionNumber
					resolution := types.V2FileContractRenewal{
						FinalRevision: finalRev,
						NewContract:   rev,
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

func TestEarlyV2Transaction(t *testing.T) {
	n := &Network{InitialTarget: types.BlockID{0xFF}}
	n.HardforkV2.AllowHeight = 1
	exp := errors.New("v2 transactions are not allowed until v2 hardfork begins")
	if err := ValidateV2Transaction(NewMidState(n.GenesisState()), types.V2Transaction{}); err == nil || err.Error() != exp.Error() {
		t.Fatalf("expected %q, got %q", exp, err)
	}
}

package consensus_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/consensus"
	rhpv2 "go.sia.tech/core/rhp/v2"
	"go.sia.tech/core/types"
)

func findBlockNonce(cs consensus.State, b *types.Block) {
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

func TestValidateBlock(t *testing.T) {
	n, genesisBlock := chain.TestnetZen()

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
	giftFC := rhpv2.PrepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), 100, rhpv2.HostSettings{}, types.VoidAddress)
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

	dbStore, checkpoint, err := chain.NewDBStore(chain.NewMemDB(), n, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}
	cs := checkpoint.State

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
	fc := rhpv2.PrepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), cs.Index.Height+1, rhpv2.HostSettings{WindowSize: 100}, types.VoidAddress)

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
	if err := consensus.ValidateBlock(cs, validBlock, dbStore.SupplementTipBlock(validBlock)); err != nil {
		t.Fatal(err)
	}

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
					b.Timestamp = b.Timestamp.AddDate(-1, 0, 0)
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
		}
		for _, test := range tests {
			corruptBlock := deepCopyBlock(b)
			test.corrupt(&corruptBlock)
			signTxn(&corruptBlock.Transactions[0])
			findBlockNonce(cs, &corruptBlock)

			if err := consensus.ValidateBlock(cs, corruptBlock, dbStore.SupplementTipBlock(corruptBlock)); err == nil {
				t.Fatalf("accepted block with %v", test.desc)
			}
		}
	}
}

func TestValidateV2Block(t *testing.T) {
	n, genesisBlock := chain.TestnetZen()

	n.HardforkTax.Height = 0
	n.HardforkFoundation.Height = 0
	n.InitialTarget = types.BlockID{0xFF}
	n.HardforkV2.AllowHeight = 0
	n.HardforkV2.RequireHeight = 1025000

	giftPrivateKey := types.GeneratePrivateKey()
	giftPublicKey := giftPrivateKey.PublicKey()
	giftAddress := types.StandardUnlockHash(giftPublicKey)
	giftAmountSC := types.Siacoins(100)
	giftAmountSF := uint64(100)
	giftPolicy := types.SpendPolicy{types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(giftPublicKey))}
	giftTxn := types.V2Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: giftAddress, Value: giftAmountSC},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Address: giftAddress, Value: giftAmountSF},
		},
	}
	genesisBlock.Transactions = nil
	genesisBlock.V2 = &types.V2BlockData{
		Transactions: []types.V2Transaction{giftTxn},
	}

	bs := consensus.V1BlockSupplement{Transactions: make([]consensus.V1TransactionSupplement, len(genesisBlock.Transactions))}
	_, cau := consensus.ApplyBlock(n.GenesisState(), genesisBlock, bs, time.Time{})

	var sces []types.SiacoinElement
	cau.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
		sces = append(sces, sce)
	})
	var sfes []types.SiafundElement
	cau.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
		sfes = append(sfes, sfe)
	})
	fmt.Println("giftPublicKey:", giftPublicKey)
	fmt.Println("giftAddress:", giftAddress)
	fmt.Println("sces[0]:", sces[0])

	dbStore, checkpoint, err := chain.NewDBStore(chain.NewMemDB(), n, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}
	cs := checkpoint.State

	signTxn := func(txn *types.V2Transaction) {
		for i := range txn.SiacoinInputs {
			// txn.SiacoinInputs[i].Signatures = append(txn.SiacoinInputs[i].Signatures, giftPrivateKey.SignHash(types.Hash256(txn.SiacoinInputs[i].ParentID)))
			txn.SiacoinInputs[i].Signatures = append(txn.SiacoinInputs[i].Signatures, giftPrivateKey.SignHash(cs.InputSigHash(*txn)))
		}
		for i := range txn.SiafundInputs {
			// txn.SiafundInputs[i].Signatures = append(txn.SiafundInputs[i].Signatures, giftPrivateKey.SignHash(types.Hash256(txn.SiafundInputs[i].ParentID)))
			txn.SiafundInputs[i].Signatures = append(txn.SiafundInputs[i].Signatures, giftPrivateKey.SignHash(cs.InputSigHash(*txn)))
		}
	}

	b := types.Block{
		ParentID:  genesisBlock.ID(),
		Timestamp: types.CurrentTimestamp(),
		V2: &types.V2BlockData{
			Height: 1,
			Transactions: []types.V2Transaction{{
				SiacoinInputs: []types.V2SiacoinInput{{
					Parent:      sces[0],
					SpendPolicy: giftPolicy,
				}},
				SiafundInputs: []types.V2SiafundInput{{
					Parent:       sfes[0],
					ClaimAddress: types.VoidAddress,
					SpendPolicy:  giftPolicy,
				}},
				SiacoinOutputs: []types.SiacoinOutput{
					{Value: giftAmountSC, Address: giftAddress},
				},
				SiafundOutputs: []types.SiafundOutput{
					{Value: giftAmountSF / 2, Address: giftAddress},
					{Value: giftAmountSF / 2, Address: types.VoidAddress},
				},
			}},
		},
		MinerPayouts: []types.SiacoinOutput{{
			Address: types.VoidAddress,
			Value:   cs.BlockReward(),
		}},
	}
	signTxn(&b.V2.Transactions[0])
	b.V2.Commitment = cs.Commitment(b.MinerPayouts[0].Address, b.Transactions, b.V2.Transactions)

	// block should be valid
	validBlock := deepCopyBlock(b)
	findBlockNonce(cs, &validBlock)
	if err := consensus.ValidateBlock(cs, validBlock, dbStore.SupplementTipBlock(validBlock)); err != nil {
		t.Fatal(err)
	}

	{
		tests := []struct {
			desc    string
			corrupt func(*types.Block)
		}{
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
					b.Timestamp = b.Timestamp.AddDate(-1, 0, 0)
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
				"siacoin input claiming incorrect unlock conditions",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]

					pk := giftPublicKey
					pk[0] ^= 255
					txn.SiacoinInputs[0].SpendPolicy = types.PolicyPublicKey(pk)
				},
			},
			{
				"siafund input claiming incorrect unlock conditions",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]

					pk := giftPublicKey
					pk[0] ^= 255
					txn.SiafundInputs[0].SpendPolicy = types.PolicyPublicKey(pk)
				},
			},
			{
				"improperly-encoded FoundationAddressUpdate",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					txn.ArbitraryData = append(types.SpecifierFoundation[:], []byte{255, 255, 255, 255, 255}...)
				},
			},
			{
				"uninitialized FoundationAddressUpdate",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					var buf bytes.Buffer
					e := types.NewEncoder(&buf)
					types.FoundationAddressUpdate{}.EncodeTo(e)
					e.Flush()
					txn.ArbitraryData = append(types.SpecifierFoundation[:], buf.Bytes()...)
				},
			},
			{
				"unsigned FoundationAddressUpdate",
				func(b *types.Block) {
					txn := &b.V2.Transactions[0]
					var buf bytes.Buffer
					e := types.NewEncoder(&buf)
					types.FoundationAddressUpdate{
						NewPrimary:  giftAddress,
						NewFailsafe: giftAddress,
					}.EncodeTo(e)
					e.Flush()
					txn.ArbitraryData = append(types.SpecifierFoundation[:], buf.Bytes()...)
				},
			},
		}
		for _, test := range tests {
			corruptBlock := deepCopyBlock(b)
			test.corrupt(&corruptBlock)
			signTxn(&corruptBlock.V2.Transactions[0])
			findBlockNonce(cs, &corruptBlock)
			b.V2.Commitment = cs.Commitment(b.MinerPayouts[0].Address, b.Transactions, b.V2.Transactions)

			if err := consensus.ValidateBlock(cs, corruptBlock, dbStore.SupplementTipBlock(corruptBlock)); err == nil {
				t.Fatalf("accepted block with %v", test.desc)
			}
		}
	}
}

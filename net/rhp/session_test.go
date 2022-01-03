package rhp

import (
	"bytes"
	"errors"
	"io"
	"math"
	"math/rand"
	"net"
	"reflect"
	"testing"
	"testing/quick"
	"time"

	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"

	"lukechampine.com/frand"
)

var randomTxn = func() types.Transaction {
	var valueFn func(t reflect.Type, r *rand.Rand) reflect.Value
	valueFn = func(t reflect.Type, r *rand.Rand) reflect.Value {
		if t.String() == "types.SpendPolicy" {
			return reflect.ValueOf(types.AnyoneCanSpend())
		}
		v := reflect.New(t).Elem()
		switch t.Kind() {
		default:
			v, _ = quick.Value(t, r)
		case reflect.Slice:
			// 3 elements per slice to prevent generating giant objects
			v.Set(reflect.MakeSlice(t, 3, 3))
			for i := 0; i < v.Len(); i++ {
				v.Index(i).Set(valueFn(t.Elem(), r))
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				v.Field(i).Set(valueFn(t.Field(i).Type, r))
			}
		}
		return v
	}
	r := rand.New(frand.NewSource())
	txn := valueFn(reflect.TypeOf(types.Transaction{}), r)
	return txn.Interface().(types.Transaction)
}()

func deepEqual(a, b types.EncoderTo) bool {
	var abuf bytes.Buffer
	e := types.NewEncoder(&abuf)
	a.EncodeTo(e)
	e.Flush()
	var bbuf bytes.Buffer
	e = types.NewEncoder(&bbuf)
	b.EncodeTo(e)
	e.Flush()
	return bytes.Equal(abuf.Bytes(), bbuf.Bytes())
}

func TestSession(t *testing.T) {
	// initialize host
	hostPrivKey := types.GeneratePrivateKey()
	hostPubKey := hostPrivKey.PublicKey()
	contractPrivKey := types.GeneratePrivateKey()
	contractPubKey := contractPrivKey.PublicKey()
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	peerErr := make(chan error, 1)
	go func() {
		peerErr <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			sess, err := AcceptSession(conn, hostPrivKey)
			if err != nil {
				return err
			}
			defer sess.Close()

			// receive+verify signed challenge
			stream, err := sess.AcceptStream()
			if err != nil {
				return err
			}
			defer stream.Close()
			var sig types.Signature
			if _, err := io.ReadFull(stream, sig[:]); err != nil {
				return err
			}
			if !sess.VerifyChallenge(sig, contractPubKey) {
				return errors.New("invalid challenge signature")
			}
			return nil
		}()
	}()

	// connect to host
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sess, err := DialSession(conn, hostPubKey)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	stream, err := sess.DialStream()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	// sign and send challenge
	sig := sess.SignChallenge(contractPrivKey)
	if _, err := stream.Write(sig[:]); err != nil {
		t.Fatal(err)
	}
	if err := <-peerErr; err != nil {
		t.Fatal(err)
	}
}

func TestChallenge(t *testing.T) {
	s := Session{}
	frand.Read(s.challenge[:])
	privkey := types.GeneratePrivateKey()
	pubkey := privkey.PublicKey()
	sig := s.SignChallenge(privkey)
	if !s.VerifyChallenge(sig, pubkey) {
		t.Fatal("challenge was not signed/verified correctly")
	}
}

func TestEncoding(t *testing.T) {
	randSignature := func() (s types.Signature) {
		frand.Read(s[:])
		return
	}
	randPubKey := func() (p types.PublicKey) {
		frand.Read(p[:])
		return
	}
	objs := []rpc.Object{
		&rpc.Specifier{'f', 'o', 'o'},
		&RPCContractRequest{
			Transactions: []types.Transaction{randomTxn},
		},
		&RPCContractAdditions{
			Parents: []types.Transaction{randomTxn},
			Inputs:  randomTxn.SiacoinInputs,
			Outputs: randomTxn.SiacoinOutputs,
		},
		&RPCContractSignatures{
			SiacoinInputSignatures: [][]types.InputSignature{
				randomTxn.SiacoinInputs[0].Signatures,
			},
			RevisionSignature: types.Signature(randomTxn.SiacoinInputs[0].Signatures[0]),
		},
		&RPCLockRequest{
			ContractID: randomTxn.FileContractRevisions[0].Parent.ID,
			Signature:  types.InputSignature(randSignature()),
			Timeout:    frand.Uint64n(100),
		},
		&RPCLockResponse{
			Revision: randomTxn.FileContractRevisions[0],
		},
		&RPCReadRequest{
			Sections:          []RPCReadRequestSection{{}},
			NewRevisionNumber: frand.Uint64n(100),
			Signature:         randSignature(),
		},
		&RPCReadResponse{
			Signature:   randSignature(),
			Data:        frand.Bytes(8),
			MerkleProof: randomTxn.SiacoinInputs[0].Parent.MerkleProof,
		},
		&RPCSectorRootsRequest{
			RootOffset:        frand.Uint64n(100),
			NumRoots:          frand.Uint64n(100),
			NewRevisionNumber: frand.Uint64n(100),
			Signature:         randSignature(),
		},
		&RPCSectorRootsResponse{
			SectorRoots: randomTxn.SiacoinInputs[0].Parent.MerkleProof,
			MerkleProof: randomTxn.SiacoinInputs[0].Parent.MerkleProof,
			Signature:   randSignature(),
		},
		&RPCSettingsResponse{
			Settings: frand.Bytes(128),
		},
		&RPCWriteRequest{
			Actions:           []RPCWriteAction{{Data: frand.Bytes(8)}},
			NewRevisionNumber: frand.Uint64n(100),
		},
		&RPCWriteMerkleProof{
			OldSubtreeHashes: randomTxn.SiacoinInputs[0].Parent.MerkleProof,
			OldLeafHashes:    randomTxn.SiacoinInputs[0].Parent.MerkleProof,
			NewMerkleRoot:    types.Hash256{4, 5, 6},
		},
		&RPCWriteResponse{
			Signature: randSignature(),
		},
		&RPCRevisionSigningResponse{
			Signature: randSignature(),
		},
		&RPCAccountBalanceResponse{
			Balance: types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		},
		&RPCAccountBalanceRequest{
			AccountID: randPubKey(),
		},
		&RPCFundAccountRequest{
			AccountID: randPubKey(),
		},
		&RPCFundAccountResponse{
			Balance: types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
			Receipt: Receipt{
				Host:      randPubKey(),
				Account:   randPubKey(),
				Amount:    types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
				Timestamp: time.Now(),
			},
			Signature: randSignature(),
		},
		&RPCExecuteInstrResponse{
			AdditionalCollateral: types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
			OutputLength:         frand.Uint64n(100),
			NewMerkleRoot:        types.Hash256(randPubKey()),
			NewDataSize:          frand.Uint64n(100),
			Proof:                randomTxn.SiacoinInputs[0].Parent.MerkleProof,
			Error:                errors.New(string(frand.Bytes(128))),
			TotalCost:            types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
			FailureRefund:        types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		},
		&RPCFinalizeProgramRequest{
			Signature:         randSignature(),
			NewRevisionNumber: frand.Uint64n(100),
			NewOutputs: ContractOutputs{
				MissedHostValue:   types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
				MissedRenterValue: types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
				ValidHostValue:    types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
				ValidRenterValue:  types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
			},
		},
	}
	for _, o := range objs {
		var b bytes.Buffer
		e := types.NewEncoder(&b)
		o.EncodeTo(e)
		e.Flush()
		dup := reflect.New(reflect.TypeOf(o).Elem()).Interface().(rpc.Object)
		d := types.NewBufDecoder(b.Bytes())
		dup.DecodeFrom(d)
		if d.Err() != nil {
			t.Errorf("error decoding %T: %v", o, d.Err())
		} else if !deepEqual(o, dup) {
			t.Errorf("%T objects differ after unmarshalling", o)
		}
	}
}

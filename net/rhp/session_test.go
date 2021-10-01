package rhp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"strings"
	"testing"

	"go.sia.tech/core/types"
)

var ErrInvalidName = errors.New("invalid name")

func randBytes(n int) []byte {
	buf := make([]byte, 8)
	rand.Read(buf)
	return buf
}

func entropy256() (e [32]byte) {
	rand.Read(e[:])
	return
}

func randUint64n(n uint64) uint64 {
	r := binary.LittleEndian.Uint64(randBytes(8))
	return r % n
}

var randomTxn = func() types.Transaction {
	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{
				SpendPolicy: types.AnyoneCanSpend(),
				Signatures:  make([]types.InputSignature, 1),
			},
		},
		// SiacoinOutputs: []types.Beneficiary{{
		// 	Address: entropy256(),
		// 	Value:   types.Siacoins(uint32(randUint64n(100))),
		// }},
		// FileContracts: []types.FileContractState{{
		// 	Filesize:       randUint64n(100),
		// 	FileMerkleRoot: entropy256(),
		// 	WindowStart:    randUint64n(100),
		// 	WindowEnd:      randUint64n(100),
		// 	Payout:         types.Siacoins(uint32(randUint64n(100))),
		// 	ValidProofOutputs: []types.SiacoinOutput{{
		// 		Value: types.Siacoins(uint32(randUint64n(100))),
		// 	}},
		// 	MissedProofOutputs: []types.SiacoinOutput{{
		// 		Value: types.Siacoins(uint32(randUint64n(100))),
		// 	}},
		// 	RevisionNumber: randUint64n(100),
		// 	UnlockHash:     entropy256(),
		// }},
		FileContractRevisions: []types.FileContractRevision{{
			Parent: types.FileContract{},
			NewState: types.FileContractState{
				RevisionNumber: randUint64n(100),
				Filesize:       randUint64n(100),
				FileMerkleRoot: entropy256(),
				WindowStart:    randUint64n(100),
				WindowEnd:      randUint64n(100),
				// ValidProofOutputs: []types.SiacoinOutput{{
				// 	Value: types.Siacoins(uint32(randUint64n(100))),
				// }},
				// MissedProofOutputs: []types.SiacoinOutput{{
				// 	Value: types.Siacoins(uint32(randUint64n(100))),
				// }},
				// UnlockHash: entropy256(),
			},
		}},
		// StorageProofs: []types.StorageProof{{
		// 	ParentID: entropy256(),
		// 	HashSet:  []types.Hash256{entropy256(), entropy256()},
		// }},
		// SiafundInputs: []types.SiafundInput{{
		// 	ClaimStart: types.Siacoins(uint32(randUint64n(100))),
		// }},
		// SiafundOutputs: []types.Beneficiary{{
		// 	Address: entropy256(),
		// 	Value:   types.Siacoins(uint32(randUint64n(100))),
		// }},
		// MinerFees:     []types.Currency{types.Siacoins(uint32(randUint64n(100)))},
		// ArbitraryData: []byte{randBytes(100)},
		// TransactionSignatures: []types.TransactionSignature{{
		// 	ParentID:       entropy256(),
		// 	CoveredFields:  types.CoveredFields{MinerFees: []uint64{1, 2, 3}},
		// 	PublicKeyIndex: randUint64n(10),
		// 	Timelock:       randUint64n(10),
		// 	Signature: randBytes(64),
		// }},
	}
	//frand.Read(txn.StorageProofs[0].Segment[:])
	return txn
}()

func deepEqual(a, b ProtocolObject) bool {
	var abuf bytes.Buffer
	e := types.NewEncoder(&abuf)
	a.encodeTo(e)
	e.Flush()
	var bbuf bytes.Buffer
	e = types.NewEncoder(&bbuf)
	b.encodeTo(e)
	e.Flush()
	return bytes.Equal(abuf.Bytes(), bbuf.Bytes())
}

type pipeRWC struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p pipeRWC) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

func (p pipeRWC) Write(b []byte) (int, error) {
	return p.w.Write(b)
}

func (p pipeRWC) Close() error {
	p.r.Close()
	return p.w.Close()
}

func newFakeConns() (io.ReadWriteCloser, io.ReadWriteCloser) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return pipeRWC{r1, w2}, pipeRWC{r2, w1}
}

type objString string

func (s *objString) encodeTo(e *types.Encoder)   { writePrefixedBytes(e, []byte(*s)) }
func (s *objString) decodeFrom(d *types.Decoder) { *s = objString(readPrefixedBytes(d)) }

func TestSession(t *testing.T) {
	renter, host := newFakeConns()
	hostErr := make(chan error, 1)
	go func() {
		hostErr <- func() error {
			hs, err := NewHostSession(host)
			if err != nil {
				return err
			}
			defer hs.Close()
			for {
				id, err := hs.ReadID()
				if errors.Is(err, ErrRenterClosed) {
					return nil
				} else if err != nil {
					return err
				}
				switch id {
				case newSpecifier("Greet"):
					var name objString
					if err := hs.ReadRequest(&name, 4096); err != nil {
						return err
					}
					if name == "" {
						err = hs.WriteResponse(nil, ErrInvalidName)
					} else {
						resp := objString("Hello, " + name)
						err = hs.WriteResponse(&resp, nil)
					}
					if err != nil {
						return err
					}
				default:
					return errors.New("unknown specifier")
				}
			}
		}()
	}()

	rs, err := NewRenterSession(renter)
	if err != nil {
		t.Fatal(err)
	}
	req := objString("Foo")
	var resp objString
	if err := rs.WriteRequest(newSpecifier("Greet"), &req); err != nil {
		t.Fatal(err)
	} else if err := rs.ReadResponse(&resp, 4096); err != nil {
		t.Fatal(err)
	} else if resp != "Hello, Foo" {
		t.Fatal("unexpected response:", resp)
	}
	req = objString("")
	if err := rs.WriteRequest(newSpecifier("Greet"), &req); err != nil {
		t.Fatal(err)
	} else if err := rs.ReadResponse(&resp, 4096); !errors.Is(err, ErrInvalidName) {
		t.Fatal(err)
	}
	if err := rs.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-hostErr; err != nil {
		t.Fatal(err)
	}
}

func TestFormContract(t *testing.T) {
	renterReq := &RPCFormContractRequest{
		Transactions: []types.Transaction{randomTxn, randomTxn},
		RenterKey:    entropy256(),
	}
	hostAdditions := &RPCFormContractAdditions{
		Parents: []types.Transaction{randomTxn, randomTxn},
		Inputs:  randomTxn.SiacoinInputs,
		Outputs: randomTxn.SiacoinOutputs,
	}
	renterSigs := &RPCFormContractSignatures{
		ContractSignatures: randomTxn.SiacoinInputs[0].Signatures,
		// RevisionSignature:  randomTxn.SiacoinInputs[0].Signatures[0],
	}
	hostSigs := &RPCFormContractSignatures{
		ContractSignatures: randomTxn.SiacoinInputs[0].Signatures,
		// RevisionSignature:  randomTxn.SiacoinInputs[0].Signatures[0],
	}

	renter, host := newFakeConns()
	hostErr := make(chan error, 1)
	go func() {
		hostErr <- func() error {
			hs, err := NewHostSession(host)
			if err != nil {
				return err
			}
			defer hs.Close()
			for {
				id, err := hs.ReadID()
				if errors.Is(err, ErrRenterClosed) {
					return nil
				} else if err != nil {
					return err
				}
				switch id {
				case RPCFormContractID:
					var req RPCFormContractRequest
					if err := hs.ReadRequest(&req, 4096); err != nil {
						return err
					} else if !deepEqual(&req, renterReq) {
						return errors.New("received request does not match sent request")
					}
					err = hs.WriteResponse(hostAdditions, nil)
					if err != nil {
						return err
					}
					var recvSigs RPCFormContractSignatures
					if err := hs.ReadResponse(&recvSigs, 4096); err != nil {
						return err
					} else if !deepEqual(&recvSigs, renterSigs) {
						return errors.New("received sigs do not match sent sigs")
					}
					err = hs.WriteResponse(hostSigs, nil)
					if err != nil {
						return err
					}
				default:
					return errors.New("unknown specifier")
				}
			}
		}()
	}()

	rs, err := NewRenterSession(renter)
	if err != nil {
		t.Fatal(err)
	}
	var recvAdditions RPCFormContractAdditions
	if err := rs.WriteRequest(RPCFormContractID, renterReq); err != nil {
		t.Fatal(err)
	} else if err := rs.ReadResponse(&recvAdditions, 4096); err != nil {
		t.Fatal(err)
	} else if !deepEqual(&recvAdditions, hostAdditions) {
		t.Fatal("received additions do not match sent additions")
	}
	var recvSigs RPCFormContractSignatures
	if err := rs.WriteResponse(renterSigs, nil); err != nil {
		t.Fatal(err)
	} else if err := rs.ReadResponse(&recvSigs, 4096); err != nil {
		t.Fatal(err)
	} else if !deepEqual(&recvSigs, hostSigs) {
		t.Fatal("received sigs do not match sent sigs")
	}
	if err := rs.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-hostErr; err != nil {
		t.Fatal(err)
	}
}

func TestChallenge(t *testing.T) {
	s := Session{}
	rand.Read(s.challenge[:])
	pubkey, privkey, _ := ed25519.GenerateKey(nil)
	sig := s.SignChallenge(privkey)
	if !s.VerifyChallenge(sig, pubkey) {
		t.Fatal("challenge was not signed/verified correctly")
	}
}

func TestEncoding(t *testing.T) {
	objs := []ProtocolObject{
		&Specifier{'f', 'o', 'o'},
		&RPCFormContractRequest{
			Transactions: []types.Transaction{randomTxn},
			RenterKey:    types.PublicKey{1, 2, 3},
		},
		&RPCFormContractAdditions{
			Parents: []types.Transaction{randomTxn},
			Inputs:  randomTxn.SiacoinInputs,
			Outputs: randomTxn.SiacoinOutputs,
		},
		&RPCFormContractSignatures{
			ContractSignatures: randomTxn.SiacoinInputs[0].Signatures,
			// RevisionSignature:  randomTxn.SiacoinInputs[0].Signatures[0],
		},
		&RPCLockRequest{
			ContractID: randomTxn.FileContractRevisions[0].Parent.ID,
			// Signature:  randBytes(64),
			Timeout: randUint64n(100),
		},
		&RPCLockResponse{
			Revision: randomTxn.FileContractRevisions[0],
			// Signatures: randomTxn.SiacoinInputs[0].Signatures,
		},
		&RPCReadRequest{
			Sections:          []RPCReadRequestSection{{}},
			NewRevisionNumber: randUint64n(100),
			//NewValidProofValues:  randomTxn.MinerFees,
			//NewMissedProofValues: randomTxn.MinerFees,
			// Signature: randBytes(64),
		},
		&RPCReadResponse{
			// Signature:   randBytes(64),
			Data:        randBytes(1024),
			MerkleProof: randomTxn.SiacoinInputs[0].Parent.MerkleProof,
		},
		&RPCSectorRootsRequest{
			RootOffset:        randUint64n(100),
			NumRoots:          randUint64n(100),
			NewRevisionNumber: randUint64n(100),
			//NewValidProofValues:  randomTxn.MinerFees,
			//NewMissedProofValues: randomTxn.MinerFees,
			// Signature: randBytes(64),
		},
		&RPCSectorRootsResponse{
			SectorRoots: randomTxn.SiacoinInputs[0].Parent.MerkleProof,
			MerkleProof: randomTxn.SiacoinInputs[0].Parent.MerkleProof,
			// Signature:   randBytes(64),
		},
		&RPCSettingsResponse{
			Settings: randBytes(100),
		},
		&RPCWriteRequest{
			Actions:           []RPCWriteAction{{Data: randBytes(1024)}},
			NewRevisionNumber: randUint64n(100),
			//NewValidProofValues:  randomTxn.MinerFees,
			//NewMissedProofValues: randomTxn.MinerFees,
		},
		&RPCWriteMerkleProof{
			OldSubtreeHashes: randomTxn.SiacoinInputs[0].Parent.MerkleProof,
			OldLeafHashes:    randomTxn.SiacoinInputs[0].Parent.MerkleProof,
			NewMerkleRoot:    types.Hash256{4, 5, 6},
		},
		&RPCWriteResponse{
			// Signature: randBytes(64),
		},
	}
	for _, o := range objs {
		var b bytes.Buffer
		e := types.NewEncoder(&b)
		o.encodeTo(e)
		e.Flush()
		dup := reflect.New(reflect.TypeOf(o).Elem()).Interface().(ProtocolObject)
		d := types.NewBufDecoder(b.Bytes())
		dup.decodeFrom(d)
		if d.Err() != nil {
			t.Errorf("error decoding %T: %v", o, d.Err())
		} else if !deepEqual(o, dup) {
			t.Errorf("%T objects differ after unmarshalling", o)
		}
	}
}

func encodedLen(o ProtocolObject) int {
	var b bytes.Buffer
	e := types.NewEncoder(&b)
	o.encodeTo(e)
	e.Flush()
	return b.Len()
}

func BenchmarkWriteMessage(b *testing.B) {
	bench := func(obj ProtocolObject) {
		name := strings.TrimPrefix(fmt.Sprintf("%T", obj), "*rhp.")
		b.Run(name, func(b *testing.B) {
			s := &Session{
				conn: struct {
					io.Writer
					io.ReadCloser
				}{ioutil.Discard, nil},
			}

			b.ResetTimer()
			b.ReportAllocs()
			b.SetBytes(int64(encodedLen(obj)))
			for i := 0; i < b.N; i++ {
				if err := s.writeMessage(obj); err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	bench(new(Specifier))
	bench(&RPCSettingsResponse{Settings: make([]byte, 4096)})
	bench(&RPCReadResponse{
		Data:        make([]byte, SectorSize),
		MerkleProof: make([]types.Hash256, 10),
	})
}

func BenchmarkReadMessage(b *testing.B) {
	bench := func(obj ProtocolObject) {
		name := strings.TrimPrefix(fmt.Sprintf("%T", obj), "*rhp.")
		b.Run(name, func(b *testing.B) {
			var buf bytes.Buffer
			(&Session{
				conn: struct {
					io.Writer
					io.ReadCloser
				}{&buf, nil},
			}).writeMessage(obj)

			var rwc struct {
				bytes.Reader
				io.WriteCloser
			}
			s := &Session{
				conn: &rwc,
			}

			b.ResetTimer()
			b.ReportAllocs()
			b.SetBytes(int64(buf.Len()))
			for i := 0; i < b.N; i++ {
				rwc.Reader.Reset(buf.Bytes())
				if err := s.readMessage(obj, uint64(buf.Len())); err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	bench(new(Specifier))
	bench(&RPCSettingsResponse{Settings: make([]byte, 4096)})
	bench(&RPCReadResponse{
		Data:        make([]byte, SectorSize),
		MerkleProof: make([]types.Hash256, 10),
	})
}

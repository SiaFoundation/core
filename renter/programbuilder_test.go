package renter

import (
	"bytes"
	"io"
	"reflect"
	"testing"

	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/types"

	"lukechampine.com/frand"
)

func TestAppendProgram(t *testing.T) {
	var sector [rhp.SectorSize]byte
	frand.Read(sector[:128])

	buf := bytes.NewBuffer(nil)
	builder := NewProgramBuilder(testSettings, buf, 10)
	builder.AddAppendSectorInstruction(&sector, true)

	instructions, requiresContract, requiresFinalization, err := builder.Program()
	switch {
	case err != nil:
		t.Fatal(err)
	case len(instructions) != 1:
		t.Fatal("wrong number of instructions")
	case !requiresContract:
		t.Fatal("program should require a contract")
	case !requiresFinalization:
		t.Fatal("program should require finalization")
	case !bytes.Equal(buf.Bytes(), sector[:]):
		t.Fatal("wrong data")
	}

	if _, ok := instructions[0].(*rhp.InstrAppendSector); !ok {
		t.Fatal("expected append sector instruction")
	}
}

func TestReadSectorProgram(t *testing.T) {
	var sector [rhp.SectorSize]byte
	frand.Read(sector[:128])
	root := rhp.SectorRoot(&sector)
	offset := frand.Uint64n(100)
	length := frand.Uint64n(100)

	buf := bytes.NewBuffer(nil)
	builder := NewProgramBuilder(testSettings, buf, 10)

	if err := builder.AddReadSectorInstruction(root, offset, length, true); err != nil {
		t.Fatal(err)
	}

	instructions, requiresContract, requiresFinalization, err := builder.Program()
	switch {
	case err != nil:
		t.Fatal(err)
	case len(instructions) != 1:
		t.Fatal("wrong number of instructions")
	case requiresContract:
		t.Fatal("program should not require a contract")
	case requiresFinalization:
		t.Fatal("program should not require finalization")
	case buf.Len() != 32+8+8:
		t.Fatalf("wrong data length expected %v, got %v", 32+8+8, buf.Len())
	}

	decoder := types.NewDecoder(io.LimitedReader{R: buf, N: 32 + 8 + 8})

	var encodedRoot types.Hash256
	encodedRoot.DecodeFrom(decoder)
	if encodedRoot != root {
		t.Fatalf("wrong root expected %v, got %v", root, encodedRoot)
	}

	encodedOffset := decoder.ReadUint64()
	if encodedOffset != offset {
		t.Fatalf("wrong offset expected %v, got %v", offset, encodedOffset)
	}

	encodedLength := decoder.ReadUint64()
	if encodedLength != length {
		t.Fatalf("wrong length expected %v, got %v", length, encodedLength)
	}

	if _, ok := instructions[0].(*rhp.InstrReadSector); !ok {
		t.Fatal("expected append sector instruction")
	}
}

func randomRegistryValue(key types.PrivateKey) (value rhp.RegistryValue) {
	value.Tweak = frand.Entropy256()
	value.Data = frand.Bytes(32)
	value.Type = rhp.RegistryValueArbitrary
	value.PublicKey = key.PublicKey()
	value.Signature = key.SignHash(value.Hash())
	return
}

func TestRegistryProgram(t *testing.T) {
	key := types.NewPrivateKeyFromSeed(frand.Entropy256())
	value := randomRegistryValue(key)
	value2 := randomRegistryValue(key)

	buf := bytes.NewBuffer(nil)
	builder := NewProgramBuilder(testSettings, buf, 10)
	builder.AddReadRegistryInstruction(value.PublicKey, value.Tweak)
	builder.AddUpdateRegistryInstruction(value)
	builder.AddReadRegistryInstruction(value2.PublicKey, value2.Tweak)

	instructions, requiresContract, requiresFinalization, err := builder.Program()
	switch {
	case err != nil:
		t.Fatal(err)
	case len(instructions) != 3:
		t.Fatal("wrong number of instructions")
	case requiresContract:
		t.Fatal("program should not require a contract")
	case requiresFinalization:
		t.Fatal("program should not require finalization")
	}

	r := bytes.NewReader(buf.Bytes())
	dec := types.NewDecoder(io.LimitedReader{R: r, N: int64(buf.Len())})

	readInstr, ok := instructions[0].(*rhp.InstrReadRegistry)
	if !ok {
		t.Fatal("expected read registry instruction")
	} else if readInstr.PublicKeyOffset != 0 {
		t.Fatal("wrong public key offset")
	} else if readInstr.TweakOffset != 32 {
		t.Fatalf("wrong tweak offset %v, expected %v", readInstr.TweakOffset, 8)
	}

	var dataPubKey types.PublicKey
	r.Seek(int64(readInstr.PublicKeyOffset), io.SeekStart)
	dataPubKey.DecodeFrom(dec)
	if dataPubKey != value.PublicKey {
		t.Fatal("wrong public key")
	}

	var dataTweak types.Hash256
	r.Seek(int64(readInstr.TweakOffset), io.SeekStart)
	dataTweak.DecodeFrom(dec)
	if dataTweak != value.Tweak {
		t.Fatal("wrong tweak")
	}

	updateInstr, ok := instructions[1].(*rhp.InstrUpdateRegistry)
	if !ok {
		t.Fatal("expected read registry instruction")
	} else if updateInstr.EntryOffset != 64 {
		t.Fatal("wrong value offset")
	}

	var dataValue rhp.RegistryValue
	r.Seek(int64(updateInstr.EntryOffset), io.SeekStart)
	dataValue.DecodeFrom(dec)
	if !reflect.DeepEqual(dataValue, value) {
		t.Fatal("wrong encoded value")
	}

	readInstr, ok = instructions[2].(*rhp.InstrReadRegistry)
	if !ok {
		t.Fatal("expected read registry instruction")
	} else if readInstr.PublicKeyOffset != uint64(buf.Len())-64 {
		t.Fatal("wrong public key offset")
	} else if readInstr.TweakOffset != uint64(buf.Len())-32 {
		t.Fatalf("wrong tweak offset %v, expected %v", readInstr.TweakOffset, 8)
	}

	r.Seek(int64(readInstr.PublicKeyOffset), io.SeekStart)
	dataPubKey.DecodeFrom(dec)
	if dataPubKey != value2.PublicKey {
		t.Fatal("wrong public key")
	}

	r.Seek(int64(readInstr.TweakOffset), io.SeekStart)
	dataTweak.DecodeFrom(dec)
	if dataTweak != value2.Tweak {
		t.Fatal("wrong tweak")
	}
}

func BenchmarkProgramBuilder(b *testing.B) {
	var sector [rhp.SectorSize]byte
	frand.Read(sector[:128])

	buf := bytes.NewBuffer(make([]byte, 0, rhp.SectorSize*b.N))
	builder := NewProgramBuilder(testSettings, buf, 10)

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(rhp.SectorSize))
	for i := 0; i < b.N; i++ {
		builder.AddAppendSectorInstruction(&sector, true)
	}
}

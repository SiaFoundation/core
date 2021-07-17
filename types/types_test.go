package types

import (
	"encoding/json"
	"testing"
)

func TestWork(t *testing.T) {
	tests := []struct {
		id  BlockID
		exp string
	}{
		{BlockID{0b11111111}, "1"},
		{BlockID{0b10000000}, "2"},
		{BlockID{0b01000000}, "4"},
		{BlockID{0b00100000}, "8"},
		{BlockID{0b00010000}, "16"},
		{BlockID{0b00001000}, "32"},
		{BlockID{0b00000100}, "64"},
		{BlockID{0b00000010}, "128"},
		{BlockID{0b00000001}, "256"},
		{BlockID{0, 0x28, 0x7E}, "1618"},                // approx 7.154 * 10^73
		{BlockID{10: 1}, "309485009821345068724781056"}, // 2^88
	}
	for _, test := range tests {
		got := WorkRequiredForHash(test.id)
		if got.String() != test.exp {
			t.Errorf("expected %v, got %v", test.exp, got)
		}
	}
}

func TestCurrencyMarshalling(t *testing.T) {
	tests := []struct {
		value, str string
	}{
		{"0", "0"},
		{"123000999", "0.123"},
		{"120000999", "0.12"},
		{"100000999", "0.1"},
		{"99999999", "0.1"},
		{"999999999", "1"},
		{"1999999999", "2"},
		{"12345678901234567890", "12345678901.235"},
	}
	for _, test := range tests {
		c, err := ParseCurrency(test.value)
		if err != nil {
			t.Fatal(err)
		} else if c.String() != test.str {
			t.Error(c.String(), test.str)
		}
		if js, err := json.Marshal(c); err != nil {
			t.Error(err)
		} else if err := json.Unmarshal(js, &c); err != nil {
			t.Error(err)
		} else if c.String() != test.str {
			t.Error(c.String(), test.str)
		}
	}
}

func BenchmarkWork(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		WorkRequiredForHash(BlockID{1})
	}
}

func BenchmarkTransactionID(b *testing.B) {
	txn := Transaction{
		SiacoinInputs:  make([]SiacoinInput, 10),
		SiacoinOutputs: make([]Beneficiary, 10),
		SiafundInputs:  make([]SiafundInput, 10),
		SiafundOutputs: make([]Beneficiary, 10),
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = txn.ID()
	}
}

func BenchmarkBlockHeaderID(b *testing.B) {
	var bh BlockHeader
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = bh.ID()
	}
}

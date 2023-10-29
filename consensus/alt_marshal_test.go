package consensus_test

import (
    "testing"
    "math/big"

    "go.sia.tech/core/consensus"
)

// Constants for test cases and error messages.
const (
    testBigIntValue        = 12345
    errMsgNegativeValue    = "value cannot be negative"
    errMsgValueOverflows   = "value overflows Work representation"
    maxBigIntString        = "115792089237316195423570985008687907853269984665640564039457584007913129639936" // 2^256 - 1
    invalidByteSliceString = "invalid"
)

func TestWorkMarshalText(t *testing.T) {
    var work consensus.Work
    testValue := big.NewInt(testBigIntValue)

    // Initialization of Work object using UnmarshalText
    if err := work.UnmarshalText([]byte(testValue.String())); err != nil {
        t.Fatalf("failed to unmarshal text: %v", err)
    }

    // Testing MarshalText
    got, err := work.MarshalText()
    if err != nil {
        t.Fatalf("expected nil error, got %v", err)
    }

    expected, err := testValue.MarshalText()
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }

    if string(got) != string(expected) {
        t.Errorf("expected %s, got %s", expected, got)
    }
}

func TestWorkUnmarshalText(t *testing.T) {
    var work consensus.Work

    // Case 1: Valid byte slice
    if err := work.UnmarshalText([]byte(big.NewInt(testBigIntValue).String())); err != nil {
        t.Fatalf("expected nil error, got %v", err)
    }

    // Case 2: Negative value
    if err := work.UnmarshalText([]byte(big.NewInt(-testBigIntValue).String())); err == nil || err.Error() != errMsgNegativeValue {
        t.Fatalf("expected error: %s, got: %v", errMsgNegativeValue, err)
    }

    // Case 3: Overflow value
    if err := work.UnmarshalText([]byte(maxBigIntString)); err == nil || err.Error() != errMsgValueOverflows {
        t.Fatalf("expected error: %s, got: %v", errMsgValueOverflows, err)
    }

    // Case 4: Invalid byte slice
    if err := work.UnmarshalText([]byte(invalidByteSliceString)); err == nil {
        t.Fatal("expected an error, got nil")
    }
}

func TestWorkJSONSerialization(t *testing.T) {
    var work consensus.Work
    if err := work.UnmarshalText([]byte("11")); err != nil {
        t.Fatalf("failed to unmarshal text: %v", err)
    }

    jsonData, err := work.MarshalJSON()
    if err != nil {
        t.Fatalf("failed to marshal JSON: %v", err)
    }

    var work2 consensus.Work
    if err := work2.UnmarshalJSON(jsonData); err != nil {
        t.Fatalf("failed to unmarshal JSON: %v", err)
    }

    if work.String() != work2.String() {
        t.Errorf("expected %v, got %v", work, work2)
    }
}
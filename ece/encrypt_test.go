// Copyright 2016 Martijn Croonen. All rights reserved.
// Use of this source code is governed by the MIT license, a copy of which can
// be found in the LICENSE file.

package ece

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestEncrypt(t *testing.T) {
	var referenceTests = []struct {
		cek        string
		nonce      string
		plaintext  string
		ciphertext string
	}{
		{"NaSfkLQbZSE50BEYen1hFw==", "RYRffTtExv5u4KY3", "I am the walrus", "G+GW8P7thruWfvqkU4rFbTvCs8rn13QmTR1cuIE3NFbv"},
		{"xl1/N9ZH1YhzUFpi4sA4lA==", "p4oN/dLo5iM8wCva", "This is part of a test", "I+x8hgURjGIsfnwGyfuCZl+zqUokVhdvRZeKXLcN/NXucGwzabswRA=="},
	}

	var keys EncryptionKeys
	for _, tt := range referenceTests {
		keys.cek, _ = base64.StdEncoding.DecodeString(tt.cek)
		keys.nonce, _ = base64.StdEncoding.DecodeString(tt.nonce)
		expected, _ := base64.StdEncoding.DecodeString(tt.ciphertext)

		input := []byte(tt.plaintext)
		cipherText, err := Encrypt(input, &keys, 0)
		if err != nil {
			t.Error("Got error while encrypting:", err)
		}

		if bytes.Compare(expected, cipherText) != 0 {
			t.Error("Error encrypting plaintext, expected", expected, "got", cipherText)
		}
	}
}

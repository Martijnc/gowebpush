// Copyright 2016 Martijn Croonen. All rights reserved.
// Use of this source code is governed by the MIT license, a copy of which can
// be found in the LICENSE file.

package ece

import "testing"

func TestEncryptionHeaderToString(t *testing.T) {
	var referenceTests = []struct {
		keyid    string
		salt     string
		rs       int
		expected string
	}{
		{"dhkey", "RYRffTtExv5u4KY3", 23, "keyid=dhkey;rs=23;salt=RYRffTtExv5u4KY3"},
		{"", "p4oN/dLo5iM8wCva", 0, "salt=p4oN/dLo5iM8wCva"},
		{"testkey", "", 0, "keyid=testkey"},
		{"salt", "salt", 300, "keyid=salt;rs=300;salt=salt"},
	}

	var header EncryptionHeader
	var result string
	for _, tt := range referenceTests {
		header.keyid = tt.keyid
		header.salt = tt.salt
		header.rs = tt.rs

		result = header.toString()
		if result != tt.expected {
			t.Error("Error serializing header, expected", tt.expected, "got", result)
		}
	}
}

func TestCryptoKeyHeaderToString(t *testing.T) {
	var referenceTests = []struct {
		keyid    string
		dh       string
		aesgcm   string
		expected string
	}{
		{"dhkey", "dh", "p4oN_dLo5iM8wCva", "keyid=dhkey;dh=dh;aesgcm=p4oN_dLo5iM8wCva"},
		{"", "BO0wJzfKZR2CdYChw1t_KnvzJ2I2giZyzaHxBJwAPUk-SNowGIC1pY6DPWUc66IjQzS206BsXhaxvxAniVT_s0U", "xl1_N9ZH1YhzUFpi4sA4lA", "dh=BO0wJzfKZR2CdYChw1t_KnvzJ2I2giZyzaHxBJwAPUk-SNowGIC1pY6DPWUc66IjQzS206BsXhaxvxAniVT_s0U;aesgcm=xl1_N9ZH1YhzUFpi4sA4lA"},
		{"testkey", "", "xl1_N9ZH1YhzUFpi4sA4lA", "keyid=testkey;aesgcm=xl1_N9ZH1YhzUFpi4sA4lA"},
		{"", "BO0wJzfKZR2CdYChw1t_KnvzJ2I2giZyzaHxBJwAPUk-SNowGIC1pY6DPWUc66IjQzS206BsXhaxvxAniVT_s0U", "p4oN_dLo5iM8wCva", "dh=BO0wJzfKZR2CdYChw1t_KnvzJ2I2giZyzaHxBJwAPUk-SNowGIC1pY6DPWUc66IjQzS206BsXhaxvxAniVT_s0U;aesgcm=p4oN_dLo5iM8wCva"},
	}

	var header CryptoKeyHeader
	var result string
	for _, tt := range referenceTests {
		header.keyid = tt.keyid
		header.dh = tt.dh
		header.aesgcm = tt.aesgcm

		result = header.toString()
		if result != tt.expected {
			t.Error("Error serializing header, expected", tt.expected, "got", result)
		}
	}
}

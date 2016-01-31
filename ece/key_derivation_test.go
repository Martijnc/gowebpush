// Copyright 2016 Martijn Croonen. All rights reserved.
// Use of this source code is governed by the MIT license, a copy of which can
// be found in the LICENSE file.

package ece

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestKeyDerivationWithAuth(t *testing.T) {
	var keys EncryptionKeys

	secret := b64("jI+o3TQMu51jthUlVwHZqCGejFXIW9QP6bEikgLmcmM=")
	rPub := b64("BN+QXXNHDGMmYGnOpUfz/G8bS4RzCFMSceKQHJImqq+4AzJLnLrppqgLkTB0AoS6hcXuSeI7UU5pG1MhRg/mJyo=")
	sPub := b64("BO0wJzfKZR2CdYChw1t/KnvzJ2I2giZyzaHxBJwAPUk+SNowGIC1pY6DPWUc66IjQzS206BsXhaxvxAniVT/s0U=")
	context := BuildDHContext(rPub, sPub)

	keys.isTest = true
	keys.salt = b64("kpN5uzoW8oaYM5E0Ti81Ew==")
	keys.preSharedAuth = b64("ezkGueTeNe/72r3dZJ2V4A==")

	keys.CreateEncryptionKeys(secret, context)

	cek := b64("/FzVZ2f0d6HU3PigqCFngA==")
	nonce := b64("p4oN/dLo5iM8wCva")

	if bytes.Compare(keys.nonce, nonce) != 0 {
		t.Error("Calculated nonce is incorrect, expected", nonce, "got", keys.nonce)
	}
	if bytes.Compare(keys.cek, cek) != 0 {
		t.Error("Calculated cek is incorrect, expected", cek, "got", keys.cek)
	}
}

func TestKeyDerivationWithoutAuth(t *testing.T) {
	var keys EncryptionKeys

	// Derived from https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00#section-5.5
	secret := b64("bdPOQQ1mAXcLBWZI3mO7Za0nmOY0ZoPunC8iq2my3cw=")
	sPub := b64("BDgpRKok2GZZDmS4r63vbJSUtcQx4Fq1V58+6+3NbZzSTlZsQiCEDTQy3CZ0ZMsqeqsEb7qW2blQHA4S48fynTk=")
	rPub := b64("BCEkBjzL8Z3C+oi2Q7oE5t2Np+p7osjGLg93qUP0wvqRT21EEWyf0cQDQcakQMqz4hQKYOQ3il2nNZct4HgAUQU=")
	context := BuildDHContext(rPub, sPub)

	keys.isTest = true
	keys.salt = b64("Qg61ZJRva/XBE9IEUelU3A==")
	keys.preSharedAuth = []byte{}

	keys.CreateEncryptionKeys(secret, context)

	cek := b64("zsDs+WYrUwwwcDj1VGOo/g==")
	nonce := b64("RYRffTtExv5u4KY3")

	if bytes.Compare(keys.nonce, nonce) != 0 {
		t.Error("Calculated nonce is incorrect, expected", nonce, "got", keys.nonce)
	}
	if bytes.Compare(keys.cek, cek) != 0 {
		t.Error("Calculated cek is incorrect, expected", cek, "got", keys.cek)
	}
}

func b64(input string) []byte {
	output, _ := base64.StdEncoding.DecodeString(input)
	return output
}

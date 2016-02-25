// Copyright 2016 Martijn Croonen. All rights reserved.
// Use of this source code is governed by the MIT license, a copy of which can
// be found in the LICENSE file.

package ece

import (
	"bytes"
	"testing"

	"github.com/martijnc/gowebpush/webpush"
)

// Tests compliance with the specification.
func TestSpecification(t *testing.T) {
	var referenceTests = []struct {
		receiverPublic string
		senderPublic   string
		senderPrivate  string
		salt           string
		auth           string
		plainText      string
		cipherText     string
	}{
		{
			"BCEkBjzL8Z3C+oi2Q7oE5t2Np+p7osjGLg93qUP0wvqRT21EEWyf0cQDQcakQMqz4hQKYOQ3il2nNZct4HgAUQU=",
			"BDgpRKok2GZZDmS4r63vbJSUtcQx4Fq1V58+6+3NbZzSTlZsQiCEDTQy3CZ0ZMsqeqsEb7qW2blQHA4S48fynTk=",
			"vG7TmzUX9NfVR4XUGBkLAFu8iDyQe+q/165JkkN0Vlw=",
			"Qg61ZJRva/XBE9IEUelU3A==",
			"",
			"I am the walrus",
			"yqD2bapcx14XxUbtwjiGx69eHE3Yd6AqXcwBpT2Kd1uy"},
		{
			"BOLcHOg4ajSHR6BjbSBeX/6aXjMu1V5RrUYXqyV/FqtQSd8RzdU1gkMv1DlRPDIUtFK6Nd16Jql0eSzyZh4V2uc=",
			"BG3OGHrl3YJ5PHpl0GSqtAAlUPnx1LvwQvFMIc68vhJU6nIkRzPEqtCduQz8wQj0r71NVPzr7ZRk2f+fhsQ5pK8=",
			"Dt1CLgQlkiaA+tmCkATyKZeoF1+Gtw1+gdEP6pOCqj4=",
			"4CQCKEyyOT/LysC17rsMXQ==",
			"r9kcFt8+4Q6MnMjJHqJoSQ==",
			"Hello, world!",
			"IiQImHDLp7FUqR/b4sDybejMaLBUH6cXnZFlUrFlUg=="},
	}

	for _, tt := range referenceTests {
		var senderKeys, receiverKeys webpush.KeyPair
		receiverKeys.SetPublicKey(b64(tt.receiverPublic))
		senderKeys.SetPublicKey(b64(tt.senderPublic))
		senderKeys.SetPrivateKey(b64(tt.senderPrivate))

		secret := webpush.CalculateSecret(&senderKeys, &receiverKeys)
		encryptionContext := BuildDHContext(receiverKeys.PublicKey, senderKeys.PublicKey)

		// Set a fixed salt for testing.
		keys := EncryptionKeys{
			isTest: true,
			salt:   b64(tt.salt),
		}

		if tt.auth != "" {
			keys.SetPreSharedAuthSecret(b64(tt.auth))
		}

		keys.CreateEncryptionKeys(secret, encryptionContext)

		input := []byte(tt.plainText)
		cipherText, err := Encrypt(input, &keys, 0)
		if err != nil {
			t.Error("Got error while encrypting:", err)
		}

		expectedCipherText := b64(tt.cipherText)
		if bytes.Compare(expectedCipherText, cipherText) != 0 {
			t.Error("Error encrypting plaintext, expected", expectedCipherText, "got", cipherText)
		}
	}
}

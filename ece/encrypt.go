// Copyright 2016 Martijn Croonen. All rights reserved.
// Use of this source code is governed by the MIT license, a copy of which can
// be found in the LICENSE file.

package ece

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// Encrypt encrypts |plaintext| using AEAD_AES_GCM_128 with the keys in |keys|
// adding |paddingLength| bytes of padding.
func Encrypt(plaintext []byte, keys *EncryptionKeys, paddingLength int) ([]byte, error) {
	if paddingLength < 0 || paddingLength > 255 {
		return nil, errors.New("Padding should be between 0 and 256.")
	}
	aes, err := aes.NewCipher(keys.cek)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}

	record := make([]byte, 1)
	if paddingLength == 0 {
		record[0] = '\x00'
	} else {
		record[0] = byte(paddingLength)
	}
	padding := make([]byte, paddingLength)
	record = append(record, padding...)
	record = append(record, plaintext...)

	var auth []byte
	return aesgcm.Seal(nil, keys.nonce, record, auth), nil
}

// Copyright 2016 Martijn Croonen. All rights reserved.
// Use of this source code is governed by the MIT license, a copy of which can
// be found in the LICENSE file.

package webpush

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestGenerateKeys(t *testing.T) {
	var kp KeyPair
	kp.GenerateKeys()

	if len(kp.PublicKey) != 65 {
		t.Error("Public key has wrong length/format, expected", 65, "got", len(kp.PublicKey))
	}

	if len(kp.privateKey) != 32 {
		t.Error("Private key has wrong length, expected", 32, "got", len(kp.privateKey))
	}
}

func TestSetPublicKey(t *testing.T) {
	var kp, gp KeyPair
	gp.GenerateKeys()

	err := kp.SetPublicKey(gp.PublicKey)
	if err != nil {
		t.Error(err)
	}

	err = kp.SetPublicKey(gp.PublicKey[1:])
	if err == nil {
		t.Error("Set incorrect key without triggering error")
	}
}

func TestSetPrivateKey(t *testing.T) {
	var kp, gp KeyPair
	gp.GenerateKeys()

	err := kp.SetPrivateKey(gp.privateKey)
	if err != nil {
		t.Error(err)
	}

	err = kp.SetPrivateKey(gp.privateKey[1:])
	if err == nil {
		t.Error("Set incorrect key without triggering error")
	}
}

func TestCalculateSecret(t *testing.T) {
	// https://github.com/beverloo/php-ece/blob/master/tests/007.phpt
	var referenceTests = []struct {
		senderPublic   string
		senderPrivate  string
		receiverPublic string
		secret         string
	}{
		{"BKrd+A8moL20GX7vSj18I+7Pdjpb8P7bpsPUrmOSbki6Sfnks5OC6UjGS2fbFqiql8jsU4oKmFBQoQh8mTDanak=", "NPWe25X9dasjrjdThj12ngF64JFxlwGehWverFTU+Fo=", "BAYdrGr+OtVn/0xt8SOMTtn5ZmT/RMi3DX7/6yhSJRCRzKHQVPdMxjkb+ETdKuilKUe2+p0y4N/u3ZqRxXDMpP8=", "QktyfLTId8zLSRlBfM2Li7c+NzsXUH9iKJaCA0uXUIU="},
		{"BHU3G5aInVGdGTffKkfhpOz3KFXDDyc3yaJPDjnRz+50dRXs/mDrBnhHSWaZ53701IZo7PqYEc0dQdiTqQcAXvU=", "1dWY+yZcoRmOxV3fwX5jN0zRYuyLVj+z8zs309TRBq8=", "BLQRZaiZSgw7q3U1ZPOFXy5W665zMRTVhxKf7fpq6SgLQreUZ+32N9lSyE9rNBxB4pvAvZ/svtmhsdZO27f3y6c=", "mW2obeYvlRRmE606GlEDV0x18D6RCYkj2JiZHO0BMZg="},
		{"BNN05pXDRedNCugLm2LiG/Fz4HxbqsWY3jjk+Im4HQycByj2PQLGkITKqatgxk3Hh2hlKXIxExQ4Says/k+fe/s=", "hvji6qFadXYcqM+oRhiHz9sEsBR9r0WQIsSCqS0U4XE=", "BF0HxMtPhJ2TFuQh01fh7xrjOccFp1ohGNQxQ1nuNNR47brRfD5GbuXDLvcOWCa5MW/yq9JIfcltBjlCfciwLNw=", "VDqV4FQdqyapjpEdP32LFUXBKt06h/HGFA+0PUHN/pY="},
		{"BIzzH3uWu5yDN3cic+NwJ+QzcCxcRYSlEHryJP87qQHhehR7lFNa0swTKyzGJcAAw1e/D+7NNkxCFIuXOsVRg/U=", "c7F2Glr+EBT8TAJ398Y0Lc0wXKg3dbqh5v21greJdaA=", "BKyjyYtoaIRX0GKranSBxQ88jDthroZdZ5fcv2vXnNiIaJUXgb8UCT8oJPv81tUZKcPuCgbyVglx8+tqjT2kHyM=", "4+AuiaAdpO95mKHeZ+iMmzUo85j03OM5pXUCNCv5qWE="},
		{"BDAoAfZ1xwF7wqwW3rf2f2beavjZpW0dRFqxiS+vnZTQDdG1jEnhO6VKPdXDnqMCNjfDBeDsg5AGnatH6BNB+HI=", "LoD2FQTM00NwHReq8aADKyUWY1HPXxRQSqM1wBOxjtc=", "BCguZbehYXK69TlplN/Jburu8svRLMPJ8U0bAy/8fTm9TMSHg7FW01ehmw3vt0VMhXXYIgClOqe0qNeVF2QcoS8=", "UKEJfdUa8u4UQq2xrHtwLzLGcyYCVnvkZ/y1TGa4Tig="},
		{"BP39yBvi1/MFRLM1JZn0BCdkY2VVOyRFd+V7ZKv1XscTpUZiVMsCrOzVjiZsM8Fbpdfl3H+Z95nZB0owLoNgtgM=", "8ZPNifhRueyGVvOOfp8cE27/fCibeJLeRQEDLd7+ixA=", "BInFq+9zvYMEVO34TOl+8Gc6wfu9YlM7YwlLTNOS7ern5pmpvz8zcwDuK5aggGYKrtBS4b7qWCNzR49VeCG6Vmk=", "Nc4LG/1oYfEc01xs+/McWlzMLH6+fW0sqGEV6I2Bnb4="},
		{"BE9gBsV7nX49Amc1mNa/Jr8/tStoP8Nx5PQGD1dB2IMpvYXhme5+myOgxqmlqFjFRft99xEgUhJF/t48C1mLV5I=", "MeEt0jpzXD+ePmlxddcXOl7rtVBCIdTZGOvgulRR2n8=", "BEnvNdE9uE4HZ0OKUcWXK7+ulkATaTJLJ9KV7ByynAFlakvWDMCuYIa/6GJ+Jw+2ylqjow7kAZphOlD2qvC93og=", "pzfk/X4ysfJAhhXF/q3RWFbtZ0I9B6F78Ej4mHlHjUE="},
		{"BCYEMCXnNfAaOewRm4HhZf3MfV8h59kCXY5U1whacKfmpSmR6jgDN+LRduLmN2fOKNOAywQ2Wy1Y0IbyiJg6BEA=", "Ls0GdHyb9EHxWoQsnCFrV+g6xDupeERlpImn7xWEjXU=", "BMQhwmOGhXCLZ/F1JjnO9ZBcdqeEnX3i5QRwXtols40bnOYzFp1Nn+svR1FLtN+zCE1C2gBVYwGdISMZjqWX0jM=", "wYZLKRaWPfYKGJULXuWpBrBag0uoN3Pm8NnG9NzETYc="},
		{"BNEBf5EGSzSYs/27jKVON0VQwUWLzC0XWZUeAdrL8rN/QvNTO5sUI2SpZT8Wm2+hbPo/zu6Y5KsoFrwiDJgCTD0=", "FQ0jxY2LeVuD6TpHsZLIOV3D92DyrFP/iU0385Ku6Kc=", "BPkeiO5JzUT/HrqNpsq6sNzCU95b9YLAiQMOGzWwO4mxtGJlLh4WZfnCpaL5nqYBFAv3YkEEg92jmRuJvrz9mFE=", "h+sLnRN7y/D7zyRt5BiVRy1iMBXz83BO3DaJ9PJg57c="},
		{"BDQiJs1zFz/MeVB7TRqFlR0XCiamhesrUOD1/ynNPXQnxES/bjivNetYaEDiQAi8kh0NTnbht99gVg0Z7C6NEEw=", "c4M8dGuoHHYmPnsi0W0w49JWv3BQncxGg18hOHzf2+Y=", "BHgSFrV+xXeFrOF0Iam++VCxNbzDqTINA5ac6bqBPsZSyZs1Oojt9m4fNLh/5yP9QwpD+jQNYA2RKGubRoR5lsU=", "KXuEaXE9NWslH7/CMjpSm7MzSmWswtDP2+RTPUiZaJM="},
	}

	var sKey, rKey KeyPair
	var expected, result, sPub, sPriv, rPub []byte
	for _, tt := range referenceTests {
		sPub, _ = base64.StdEncoding.DecodeString(tt.senderPublic)
		sPriv, _ = base64.StdEncoding.DecodeString(tt.senderPrivate)
		rPub, _ = base64.StdEncoding.DecodeString(tt.receiverPublic)
		expected, _ = base64.StdEncoding.DecodeString(tt.secret)

		sKey.SetPublicKey(sPub)
		sKey.SetPrivateKey(sPriv)
		rKey.SetPublicKey(rPub)

		result = CalculateSecret(&sKey, &rKey)
		if bytes.Compare(result, expected) != 0 {
			t.Error("Error calculating secret, expected", tt.secret, "got", base64.StdEncoding.EncodeToString(result))
		}
	}
}

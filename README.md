# gowebpush
Go package for implementing Encrypted Content-Encoding for Web Push.

```go
var sp, rp webpush.KeyPair
sp.GenerateKeys()
rp.SetPublicKey(/* NIST P-256 public key (from browser) in uncompressed format */)
// Calculate the shared secret from the key-pairs (IKM).
secret := webpush.CalculateSecret(&sp, &rp)

var keys ece.EncryptionKeys
encryptionContext := ece.BuildDHContext(rp.PublicKey, sp.PublicKey)
keys.SetPreSharedAuthSecret(/* Client auth (from browser) */)

// The current Firefox nightly build doesn't take the auth and context into account
// when decrypting the payload.
if strings.Contains(subscription.Endpoint, "mozilla") {
	encryptionContext = []byte{}
	keys.SetPreSharedAuthSecret([]byte{})
}

// Derive the encryption key and nonce from the input keying material.
keys.CreateEncryptionKeys(secret, encryptionContext)

// Encrypt the plaintext
ciphertext, _ := ece.Encrypt([]byte(message), &keys, 25)

// Create the headers
var eh ece.EncryptionHeader
eh.SetSalt(keys.GetSalt())
eh.SetRecordSize(len(ciphertext))

var ckh ece.CryptoKeyHeader
ckh.SetDHKey(sp.PublicKey)

// Create the ECE request.
client := urlfetch.Client(*context)
r := ece.CreateRequest(*client, prepareEndpoint(subscription.Endpoint), ciphertext, &ckh, &eh)
if strings.Contains(subscription.Endpoint, "google") {
	r.Header.Add("Authorization", "key=AIzaSyCR30h2cngxdbwxAoZpD-fGxfUzrGPmmSs")
}

// And submit.
response, err := client.Do(r)
if err != nil {
	panic(err)
}
defer response.Body.Close()

if response.StatusCode == 201 {
	// Success.
} else {
	// Fail.
}
```

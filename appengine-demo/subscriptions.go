package webpush

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/martijnc/gowebpush/ece"
	"github.com/martijnc/gowebpush/webpush"

	"golang.org/x/net/context"

	"google.golang.org/appengine"
	"google.golang.org/appengine/urlfetch"
)

func init() {
	http.HandleFunc("/send-push/", push)
}

func push(w http.ResponseWriter, r *http.Request) {
	context := appengine.NewContext(r)
	var payload = r.FormValue("payload")

	AuthKey, err := base64.StdEncoding.DecodeString(r.FormValue("auth"))
	if err != nil {
		fmt.Fprintln(w, err)
	}

	P256dhKey, err := base64.StdEncoding.DecodeString(r.FormValue("p256dh"))
	if err != nil {
		fmt.Fprintln(w, err)
	}

	endpoint := r.FormValue("endpoint")

	success, err := sendPushMessage(endpoint, P256dhKey, AuthKey, payload, &context)
	if success {
		fmt.Fprintln(w, "Push message send succesfully.")
	} else {
		fmt.Fprintln(w, "Failed to send the push message.")
	}
}

func sendPushMessage(endpoint string, p256dh, auth []byte, message string, context *context.Context) (bool, error) {
	var sp, rp webpush.KeyPair
	sp.GenerateKeys()
	err := rp.SetPublicKey(p256dh)
	if err != nil {
		return false, err
	}

	// Calculate the shared secret from the key-pairs (IKM).
	secret := webpush.CalculateSecret(&sp, &rp)

	var keys ece.EncryptionKeys
	encryptionContext := ece.BuildDHContext(rp.PublicKey, sp.PublicKey)
	keys.SetPreSharedAuthSecret(auth)

	// The current Firefox nightly build doesn't take the auth and context into account
	// when decrypting the payload.
	if strings.Contains(endpoint, "mozilla") {
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
	r := ece.CreateRequest(*client, prepareEndpoint(endpoint), ciphertext, &ckh, &eh, 600)
	if strings.Contains(endpoint, "google") {
		r.Header.Add("Authorization", "key=AIzaSyBopqMP1DH7zbT0IyoKIzTAtBAZQPNN6oY")
	}

	// And submit.
	response, err := client.Do(r)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	if response.StatusCode != 201 {
		return false, errors.New("Push endpoint returned incorrect status code: " + strconv.Itoa(response.StatusCode))
	}
	return true, nil
}

// Use Google's Web Push compatible server rather the the GCM one.
func prepareEndpoint(endpoint string) string {
	return strings.Replace(endpoint, "https://android.googleapis.com/gcm/send/", "https://jmt17.google.com/gcm/demo-webpush-00/", -1)
}

// FromURLBase64 is a utility function for parsing url-safe base64 without padding.
func FromURLBase64(base64url string) ([]byte, error) {
	// The padding may be omitted from the base64 url encoded string (as Chrome does)
	// but the Go base64 decoder trips over this. So add padding when needed before decoding.
	if l := len(base64url) % 4; l > 0 {
		base64url += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(base64url)
}

// nauth emulates NAS, which provides GameSpy credentials among other things.
// Mahoumemo does not need NAS. It only exists to satisfy connection requirements.
// For now, nauth sends placeholder values.

// TODO: make sure "token" field in login is correct format

package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type AuthServer struct{}

func main() {
	proto := flag.String("proto", "tcp", "protocol to use (\"tcp\", \"unix\", etc)")
	addr := flag.String("addr", "0.0.0.0:8100", "address to listen on")
	flag.Parse()

	listener, err := net.Listen(*proto, *addr)
	if err != nil {
		log.Fatalf("failed to create %s listener on %s: %s", *proto, *addr, err)
	}

	if *proto == "unix" {
		os.Chmod(*addr, 0777)
	}

	http.Serve(listener, &AuthServer{})
}

func (s *AuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %s", err), http.StatusBadRequest)
		return
	}

	params, err := url.ParseQuery(string(body))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to decode request body: %s", err), http.StatusBadRequest)
		return
	}

	resp := make(url.Values)

	switch r.URL.Path {
	case "/ac": // account
		action := decode(params.Get("action"))
		if action == "" {
			http.Error(w, "missing action parameter", http.StatusBadRequest)
			return
		}

		switch action {
		case "acctcreate":
			resp.Set("retry", encode("0"))
			resp.Set("returncd", encode("002"))
			resp.Set("userid", encode("1234567890000"))
		case "login":
			resp.Set("challenge", encode(randString(8)))
			resp.Set("locator", encode("gamespy.com"))
			resp.Set("retry", encode("0"))
			resp.Set("returncd", encode("001"))
			resp.Set("token", encode(append([]byte("NDS"), randBytes(96)...)))
		case "svcloc":
			// unused
		}
	case "/pr": // profanity check
		var prwords string
		for i := 0; i < len(strings.Split(decode(params.Get("words")), "\t")); i++ {
			prwords += "0"
		}

		resp.Set("prwords", encode(prwords))
		resp.Set("returncd", encode("000"))
	default:
		http.Error(w, "unknown endpoint", http.StatusNotFound)
		return
	}

	// always present
	resp.Set("datetime", encode(time.Now().UTC().Format("20060102150405")))

	w.Write([]byte(resp.Encode()))
}

const randStringChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func randBytes(amount int) []byte {
	buf := make([]byte, amount)

	rand.Read(buf)

	return buf
}

func randString(amount int) string {
	buf := randBytes(amount)

	for k, v := range buf {
		buf[k] = randStringChars[int(v)%len(randStringChars)]
	}

	return string(buf)
}

func decode(data string) string {
	decoded, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(data, "*", "="))
	return string(decoded)
}

func encode(data any) string {
	var encoded string

	switch data := data.(type) {
	case string:
		encoded = base64.StdEncoding.EncodeToString([]byte(data))
	case []byte:
		encoded = base64.StdEncoding.EncodeToString(data)
	}

	return strings.ReplaceAll(encoded, "=", "*")
}

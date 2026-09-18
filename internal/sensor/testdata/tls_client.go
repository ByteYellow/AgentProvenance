// An unstripped Go ABIInternal client for the opt-in live sensor acceptance.
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: tls-client URL MARKER")
	}
	// The acceptance starts its own loopback TLS server with a temporary cert.
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // local fixture only
	}}
	resp, err := client.Post(os.Args[1], "application/json", strings.NewReader(fmt.Sprintf(`{"marker":%q}`, os.Args[2])))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		panic(err)
	}
	if resp.StatusCode != http.StatusOK {
		panic(resp.Status)
	}
}

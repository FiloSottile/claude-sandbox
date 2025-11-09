package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

var (
	serverURL = flag.String("server", "", "keyserver URL (default from AGE_KEYSERVER_URL or http://localhost:13889)")
)

func main() {
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: age-keyserver [flags] <email>\n")
		fmt.Fprintf(os.Stderr, "\nLook up an age public key by email address.\n\n")
		fmt.Fprintf(os.Stderr, "Example:\n")
		fmt.Fprintf(os.Stderr, "  age-keyserver filippo@example.com\n")
		fmt.Fprintf(os.Stderr, "  age -r $(age-keyserver filippo@example.com) -o secret.age secret.txt\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment:\n")
		fmt.Fprintf(os.Stderr, "  AGE_KEYSERVER_URL  Default keyserver URL\n")
		os.Exit(2)
	}

	email := flag.Arg(0)

	// Determine server URL
	server := *serverURL
	if server == "" {
		server = os.Getenv("AGE_KEYSERVER_URL")
	}
	if server == "" {
		server = "http://localhost:13889"
	}

	pubkey, err := lookupKey(server, email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(pubkey)
}

func lookupKey(serverURL, email string) (string, error) {
	// Build the lookup URL
	lookupURL := serverURL + "/lookup?email=" + url.QueryEscape(email)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Make the request
	resp, err := client.Get(lookupURL)
	if err != nil {
		return "", fmt.Errorf("failed to connect to keyserver: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("no key found for %s", email)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("keyserver error: %s - %s", resp.Status, string(body))
	}

	// Parse JSON response
	var result struct {
		Email  string `json:"email"`
		Pubkey string `json:"pubkey"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Pubkey == "" {
		return "", fmt.Errorf("empty public key returned")
	}

	return result.Pubkey, nil
}

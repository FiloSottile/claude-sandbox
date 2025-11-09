package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// hCaptcha test keys from https://docs.hcaptcha.com/
const (
	// This test key always passes validation
	hcaptchaTestResponsePass = "10000000-aaaa-bbbb-cccc-000000000001"
	// This secret key is used for testing
	hcaptchaTestSecret = "0x0000000000000000000000000000000000000000"

	// Test schema without trailing whitespace
	testSchema = `CREATE TABLE IF NOT EXISTS keys (email TEXT PRIMARY KEY, json_data BLOB) STRICT`
)

// setupTestServer creates a test server with an in-memory database
func setupTestServer(t *testing.T) *Server {
	t.Helper()

	// Generate test HMAC key
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		t.Fatalf("failed to generate HMAC key: %v", err)
	}

	// Create in-memory database
	dbpool, err := sqlitex.NewPool("file::memory:?mode=memory&cache=shared", sqlitex.PoolOptions{
		PoolSize: 10,
		PrepareConn: func(conn *sqlite.Conn) error {
			return sqlitex.ExecuteTransient(conn, testSchema, nil)
		},
	})
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}
	t.Cleanup(func() { dbpool.Close() })

	// Parse templates
	templates := parseTestTemplates(t)

	return &Server{
		dbpool:    dbpool,
		templates: templates,
		hmacKey:   hmacKey,
		baseURL:   "http://localhost:13889",
	}
}

func parseTestTemplates(t *testing.T) *template.Template {
	t.Helper()
	tmplFS, err := fs.Sub(embeddedFS, "templates")
	if err != nil {
		t.Fatalf("failed to get templates subdirectory: %v", err)
	}
	return template.Must(template.ParseFS(tmplFS, "*.html"))
}

// generateTestKey generates a valid age public key for testing
func generateTestKey(t *testing.T) string {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return identity.Recipient().String()
}

func TestHandleLookup(t *testing.T) {
	srv := setupTestServer(t)

	tests := []struct {
		name           string
		email          string
		setupKey       bool
		expectedStatus int
		expectedKey    string
	}{
		{
			name:           "key exists",
			email:          "test@example.com",
			setupKey:       true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "key not found",
			email:          "nonexistent@example.com",
			setupKey:       false,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "missing email parameter",
			email:          "",
			setupKey:       false,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testKey string
			if tt.setupKey {
				testKey = generateTestKey(t)
				if err := srv.storeKey(tt.email, testKey); err != nil {
					t.Fatalf("failed to setup test key: %v", err)
				}
			}

			req := httptest.NewRequest("GET", "/api/lookup?email="+url.QueryEscape(tt.email), nil)
			w := httptest.NewRecorder()

			srv.handleLookup(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var resp struct {
					Email  string `json:"email"`
					Pubkey string `json:"pubkey"`
				}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.Email != tt.email {
					t.Errorf("expected email %s, got %s", tt.email, resp.Email)
				}
				if resp.Pubkey != testKey {
					t.Errorf("expected pubkey %s, got %s", testKey, resp.Pubkey)
				}
			}
		})
	}
}

func TestHandleSetKey(t *testing.T) {
	srv := setupTestServer(t)
	email := "test@example.com"

	tests := []struct {
		name           string
		pubkey         string
		validAuth      bool
		expectedStatus int
		expectStored   bool
	}{
		{
			name:           "create new key",
			pubkey:         generateTestKey(t),
			validAuth:      true,
			expectedStatus: http.StatusOK,
			expectStored:   true,
		},
		{
			name:           "update existing key",
			pubkey:         generateTestKey(t),
			validAuth:      true,
			expectedStatus: http.StatusOK,
			expectStored:   true,
		},
		{
			name:           "delete key (empty pubkey)",
			pubkey:         "",
			validAuth:      true,
			expectedStatus: http.StatusOK,
			expectStored:   false,
		},
		{
			name:           "invalid auth",
			pubkey:         generateTestKey(t),
			validAuth:      false,
			expectedStatus: http.StatusUnauthorized,
			expectStored:   false,
		},
		{
			name:           "invalid key format",
			pubkey:         "not-a-valid-age-key",
			validAuth:      true,
			expectedStatus: http.StatusBadRequest,
			expectStored:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate auth parameters
			var sig, ts string
			if tt.validAuth {
				sig, ts = generateValidAuth(t, srv, email)
			} else {
				sig, ts = "invalid-sig", "123456789"
			}

			// Create request
			form := url.Values{}
			form.Set("email", email)
			form.Set("sig", sig)
			form.Set("ts", ts)
			form.Set("pubkey", tt.pubkey)

			req := httptest.NewRequest("POST", "/setkey", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			srv.handleSetKey(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Verify storage
			if tt.expectedStatus == http.StatusOK {
				storedKey := srv.getCurrentKey(email)
				if tt.expectStored && storedKey != tt.pubkey {
					t.Errorf("expected stored key %s, got %s", tt.pubkey, storedKey)
				}
				if !tt.expectStored && storedKey != "" {
					t.Errorf("expected no stored key, got %s", storedKey)
				}
			}
		})
	}
}

func TestHandleVerifyToken(t *testing.T) {
	srv := setupTestServer(t)
	email := "test@example.com"

	// Store a test key
	testKey := generateTestKey(t)
	if err := srv.storeKey(email, testKey); err != nil {
		t.Fatalf("failed to store test key: %v", err)
	}

	tests := []struct {
		name           string
		validAuth      bool
		expectedStatus int
		expectKey      bool
	}{
		{
			name:           "valid token with existing key",
			validAuth:      true,
			expectedStatus: http.StatusOK,
			expectKey:      true,
		},
		{
			name:           "invalid token",
			validAuth:      false,
			expectedStatus: http.StatusUnauthorized,
			expectKey:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sig, ts string
			if tt.validAuth {
				sig, ts = generateValidAuth(t, srv, email)
			} else {
				sig, ts = "invalid-sig", "123456789"
			}

			reqBody := map[string]string{
				"email": email,
				"sig":   sig,
				"ts":    ts,
			}
			body, _ := json.Marshal(reqBody)

			req := httptest.NewRequest("POST", "/api/verify-token", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			srv.handleVerifyToken(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var resp struct {
					CurrentKey string `json:"currentKey"`
				}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if tt.expectKey && resp.CurrentKey != testKey {
					t.Errorf("expected key %s, got %s", testKey, resp.CurrentKey)
				}
			}
		})
	}
}

func TestHandleLogin(t *testing.T) {
	srv := setupTestServer(t)

	// Set test hCaptcha secret for these tests
	oldSecret := os.Getenv("HCAPTCHA_SECRET")
	os.Setenv("HCAPTCHA_SECRET", hcaptchaTestSecret)
	defer func() {
		if oldSecret != "" {
			os.Setenv("HCAPTCHA_SECRET", oldSecret)
		} else {
			os.Unsetenv("HCAPTCHA_SECRET")
		}
	}()

	tests := []struct {
		name            string
		email           string
		captchaResponse string
		expectedStatus  int
	}{
		{
			name:            "valid request",
			email:           "test@example.com",
			captchaResponse: hcaptchaTestResponsePass,
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "missing email",
			email:           "",
			captchaResponse: hcaptchaTestResponsePass,
			expectedStatus:  http.StatusBadRequest,
		},
		{
			name:            "missing captcha",
			email:           "test@example.com",
			captchaResponse: "",
			expectedStatus:  http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Set("email", tt.email)
			form.Set("h-captcha-response", tt.captchaResponse)

			req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			srv.handleLogin(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestHCaptchaVerification(t *testing.T) {
	// Test with actual hCaptcha API using test keys
	oldSecret := os.Getenv("HCAPTCHA_SECRET")
	os.Setenv("HCAPTCHA_SECRET", hcaptchaTestSecret)
	defer func() {
		if oldSecret != "" {
			os.Setenv("HCAPTCHA_SECRET", oldSecret)
		} else {
			os.Unsetenv("HCAPTCHA_SECRET")
		}
	}()

	tests := []struct {
		name     string
		response string
		expected bool
	}{
		{
			name:     "valid test response",
			response: hcaptchaTestResponsePass,
			expected: true,
		},
		{
			name:     "empty response",
			response: "",
			expected: false,
		},
		{
			name:     "invalid response",
			response: "invalid-response-token",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifyCaptcha(tt.response)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestHCaptchaDevelopmentMode(t *testing.T) {
	// Ensure HCAPTCHA_SECRET is not set
	oldSecret := os.Getenv("HCAPTCHA_SECRET")
	os.Unsetenv("HCAPTCHA_SECRET")
	defer func() {
		if oldSecret != "" {
			os.Setenv("HCAPTCHA_SECRET", oldSecret)
		}
	}()

	// In development mode (no secret), any non-empty response should pass
	result := verifyCaptcha("any-value")
	if !result {
		t.Error("expected captcha to pass in development mode")
	}

	// Empty response should still fail
	result = verifyCaptcha("")
	if result {
		t.Error("expected empty captcha response to fail even in development mode")
	}
}

func TestAuthenticationFlow(t *testing.T) {
	srv := setupTestServer(t)
	email := "test@example.com"
	testKey := generateTestKey(t)

	// Step 1: Generate login link
	req := httptest.NewRequest("GET", "/", nil)
	loginLink := srv.generateLoginLink(email, req)

	// Parse the login link
	u, err := url.Parse(loginLink)
	if err != nil {
		t.Fatalf("failed to parse login link: %v", err)
	}

	// Extract fragment parameters
	fragment := u.Fragment
	params, err := url.ParseQuery(fragment)
	if err != nil {
		t.Fatalf("failed to parse fragment: %v", err)
	}

	emailParam := params.Get("email")
	sig := params.Get("sig")
	ts := params.Get("ts")

	if emailParam != email {
		t.Errorf("expected email %s, got %s", email, emailParam)
	}

	// Step 2: Verify the token
	verifyReq := map[string]string{
		"email": email,
		"sig":   sig,
		"ts":    ts,
	}
	body, _ := json.Marshal(verifyReq)

	req = httptest.NewRequest("POST", "/api/verify-token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleVerifyToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("token verification failed: status %d", w.Code)
	}

	// Step 3: Set a key using the authenticated token
	form := url.Values{}
	form.Set("email", email)
	form.Set("sig", sig)
	form.Set("ts", ts)
	form.Set("pubkey", testKey)

	req = httptest.NewRequest("POST", "/setkey", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()

	srv.handleSetKey(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("setkey failed: status %d", w.Code)
	}

	// Step 4: Lookup the key
	req = httptest.NewRequest("GET", "/api/lookup?email="+url.QueryEscape(email), nil)
	w = httptest.NewRecorder()

	srv.handleLookup(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("lookup failed: status %d", w.Code)
	}

	var resp struct {
		Email  string `json:"email"`
		Pubkey string `json:"pubkey"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Pubkey != testKey {
		t.Errorf("expected pubkey %s, got %s", testKey, resp.Pubkey)
	}
}

func TestTokenExpiration(t *testing.T) {
	srv := setupTestServer(t)
	email := "test@example.com"

	// Generate a token with a timestamp 11 minutes in the past
	oldTime := time.Now().Add(-11 * time.Minute)
	ts := oldTime.Unix()
	sig := generateSigForTimestamp(srv, email, ts)

	// Try to verify the expired token
	reqBody := map[string]string{
		"email": email,
		"sig":   sig,
		"ts":    fmt.Sprintf("%d", ts),
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/verify-token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleVerifyToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected expired token to be unauthorized, got status %d", w.Code)
	}
}

// Helper functions

func generateValidAuth(t *testing.T, srv *Server, email string) (sig, ts string) {
	t.Helper()
	now := time.Now().Unix()
	ts = strconv.FormatInt(now, 10)
	sig = generateSigForTimestamp(srv, email, now)
	return
}

func generateSigForTimestamp(srv *Server, email string, ts int64) string {
	msg := fmt.Sprintf("%s:%d", email, ts)
	h := hmac.New(sha256.New, srv.hmacKey)
	h.Write([]byte(msg))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

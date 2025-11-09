package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

var (
	//go:embed templates static
	embeddedFS embed.FS

	dbPath     = flag.String("db", "keyserver.sqlite3", "path to SQLite database")
	listenAddr = flag.String("listen", "localhost:13889", "address to listen on")
)

type Server struct {
	db        *sql.DB
	templates *template.Template
	hmacKey   []byte
}

type KeyData struct {
	Pubkey    string `json:"pubkey"`
	UpdatedAt int64  `json:"updated_at"`
}

const (
	linkValidDuration = 10 * time.Minute
	schema            = `
		CREATE TABLE IF NOT EXISTS keys (
			email TEXT PRIMARY KEY,
			json_data BLOB
		) STRICT;
	`
)

func main() {
	flag.Parse()

	// Check for development vs production mode
	postmarkToken := os.Getenv("POSTMARK_TOKEN")
	if postmarkToken == "" {
		log.Println("Running in DEVELOPMENT mode (POSTMARK_TOKEN not set)")
		log.Println("Login links will be logged to console instead of emailed")
	}

	// Generate random HMAC key
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		log.Fatal("failed to generate HMAC key:", err)
	}
	log.Printf("Generated HMAC key (will invalidate on restart)")

	// Initialize database
	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		log.Fatal("failed to open database:", err)
	}
	defer db.Close()

	// Create schema
	if _, err := db.Exec(schema); err != nil {
		log.Fatal("failed to create schema:", err)
	}

	// Parse templates
	tmplFS, err := fs.Sub(embeddedFS, "templates")
	if err != nil {
		log.Fatal("failed to get templates subdirectory:", err)
	}
	templates := template.Must(template.ParseFS(tmplFS, "*.html"))

	// Create server
	srv := &Server{
		db:        db,
		templates: templates,
		hmacKey:   hmacKey,
	}

	// Set up routes
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", srv.handleHome)
	mux.HandleFunc("POST /login", srv.handleLogin)
	mux.HandleFunc("GET /auth", srv.handleAuth)
	mux.HandleFunc("POST /setkey", srv.handleSetKey)
	mux.HandleFunc("GET /lookup", srv.handleLookup)

	// Serve static files
	staticFS, err := fs.Sub(embeddedFS, "static")
	if err != nil {
		log.Fatal("failed to get static subdirectory:", err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Start server with h2c support
	log.Printf("Starting server on %s", *listenAddr)
	if err := http.ListenAndServe(*listenAddr, h2cHandler(mux)); err != nil {
		log.Fatal("server error:", err)
	}
}

// h2cHandler wraps the handler to support HTTP/2 cleartext
func h2cHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Support HTTP/2 over cleartext
		if r.ProtoMajor == 2 && r.Header.Get("Upgrade") == "" {
			h.ServeHTTP(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if err := s.templates.ExecuteTemplate(w, "home.html", nil); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("template error: %v", err)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	captchaResponse := r.FormValue("h-captcha-response")

	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	// Verify captcha
	if !verifyCaptcha(captchaResponse) {
		http.Error(w, "Captcha verification failed", http.StatusBadRequest)
		return
	}

	// Generate login link
	loginLink := s.generateLoginLink(email, r)

	// Send email via Postmark
	if err := sendLoginEmail(email, loginLink); err != nil {
		http.Error(w, "Failed to send email", http.StatusInternalServerError)
		log.Printf("email error: %v", err)
		return
	}

	// Show confirmation page
	if err := s.templates.ExecuteTemplate(w, "login_sent.html", map[string]string{
		"Email": email,
	}); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("template error: %v", err)
	}
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	sig := r.URL.Query().Get("sig")
	ts := r.URL.Query().Get("ts")

	if email == "" || sig == "" || ts == "" {
		http.Error(w, "Invalid login link", http.StatusBadRequest)
		return
	}

	// Verify signature and timestamp
	if !s.verifyLoginLink(email, sig, ts) {
		http.Error(w, "Invalid or expired login link", http.StatusUnauthorized)
		return
	}

	// Get current key if exists
	currentKey := s.getCurrentKey(email)

	// Show set key page
	if err := s.templates.ExecuteTemplate(w, "setkey.html", map[string]string{
		"Email":      email,
		"Sig":        sig,
		"Ts":         ts,
		"CurrentKey": currentKey,
	}); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("template error: %v", err)
	}
}

func (s *Server) handleSetKey(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	sig := r.FormValue("sig")
	ts := r.FormValue("ts")
	pubkey := strings.TrimSpace(r.FormValue("pubkey"))

	// Verify auth
	if !s.verifyLoginLink(email, sig, ts) {
		http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
		return
	}

	// Validate age public key
	if pubkey != "" {
		if _, err := age.ParseX25519Recipient(pubkey); err != nil {
			http.Error(w, "Invalid age public key format", http.StatusBadRequest)
			return
		}

		// Store in database
		if err := s.storeKey(email, pubkey); err != nil {
			http.Error(w, "Failed to store key", http.StatusInternalServerError)
			log.Printf("database error: %v", err)
			return
		}
	} else {
		// Delete key
		if err := s.deleteKey(email); err != nil {
			http.Error(w, "Failed to delete key", http.StatusInternalServerError)
			log.Printf("database error: %v", err)
			return
		}
	}

	// Show success page
	if err := s.templates.ExecuteTemplate(w, "success.html", map[string]string{
		"Email":  email,
		"Pubkey": pubkey,
	}); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("template error: %v", err)
	}
}

func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "Email parameter required", http.StatusBadRequest)
		return
	}

	pubkey := s.getCurrentKey(email)
	if pubkey == "" {
		http.Error(w, "No key found for this email", http.StatusNotFound)
		return
	}

	// Return as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"email":  email,
		"pubkey": pubkey,
	})
}

func (s *Server) generateLoginLink(email string, r *http.Request) string {
	ts := time.Now().Unix()
	msg := fmt.Sprintf("%s:%d", email, ts)

	h := hmac.New(sha256.New, s.hmacKey)
	h.Write([]byte(msg))
	sig := base64.URLEncoding.EncodeToString(h.Sum(nil))

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, r.Host)

	return fmt.Sprintf("%s/auth?email=%s&ts=%d&sig=%s",
		baseURL,
		url.QueryEscape(email),
		ts,
		url.QueryEscape(sig))
}

func (s *Server) verifyLoginLink(email, sig, tsStr string) bool {
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}

	// Check if expired
	if time.Since(time.Unix(ts, 0)) > linkValidDuration {
		return false
	}

	// Verify HMAC
	msg := fmt.Sprintf("%s:%d", email, ts)
	h := hmac.New(sha256.New, s.hmacKey)
	h.Write([]byte(msg))
	expectedSig := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(sig), []byte(expectedSig))
}

func (s *Server) getCurrentKey(email string) string {
	var jsonData []byte
	err := s.db.QueryRow("SELECT json_data FROM keys WHERE email = ?", email).Scan(&jsonData)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("database error: %v", err)
		}
		return ""
	}

	var data KeyData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		log.Printf("json unmarshal error: %v", err)
		return ""
	}

	return data.Pubkey
}

func (s *Server) storeKey(email, pubkey string) error {
	data := KeyData{
		Pubkey:    pubkey,
		UpdatedAt: time.Now().Unix(),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`
		INSERT INTO keys (email, json_data)
		VALUES (?, JSONB(?))
		ON CONFLICT(email) DO UPDATE SET
			json_data = excluded.json_data
	`, email, string(jsonData))
	return err
}

func (s *Server) deleteKey(email string) error {
	_, err := s.db.Exec("DELETE FROM keys WHERE email = ?", email)
	return err
}

func verifyCaptcha(response string) bool {
	if response == "" {
		return false
	}

	hcaptchaSecret := os.Getenv("HCAPTCHA_SECRET")
	if hcaptchaSecret == "" {
		log.Println("HCAPTCHA_SECRET not set, skipping captcha verification")
		return true // Allow in development
	}

	data := url.Values{}
	data.Set("secret", hcaptchaSecret)
	data.Set("response", response)

	resp, err := http.PostForm("https://hcaptcha.com/siteverify", data)
	if err != nil {
		log.Printf("captcha verification error: %v", err)
		return false
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("captcha response decode error: %v", err)
		return false
	}

	return result.Success
}

func sendLoginEmail(email, loginLink string) error {
	postmarkToken := os.Getenv("POSTMARK_TOKEN")
	if postmarkToken == "" {
		// Development mode: log the link instead of emailing
		log.Printf("=== DEVELOPMENT MODE: Login link for %s ===", email)
		log.Printf("Click this link to login: %s", loginLink)
		log.Printf("Link expires in 10 minutes")
		log.Printf("==========================================")
		return nil
	}

	emailBody := map[string]interface{}{
		"From":     "noreply@example.com", // TODO: configure this
		"To":       email,
		"Subject":  "Login to Age Keyserver",
		"TextBody": fmt.Sprintf("Click this link to login and manage your age public key:\n\n%s\n\nThis link will expire in 10 minutes.", loginLink),
		"HtmlBody": fmt.Sprintf(`<p>Click this link to login and manage your age public key:</p><p><a href="%s">%s</a></p><p>This link will expire in 10 minutes.</p>`, loginLink, loginLink),
	}

	body, err := json.Marshal(emailBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", "https://api.postmarkapp.com/email", strings.NewReader(string(body)))
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Postmark-Server-Token", postmarkToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("postmark API error: %s - %s", resp.Status, string(body))
	}

	return nil
}

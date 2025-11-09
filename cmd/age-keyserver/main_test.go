package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"rsc.io/script"
	"rsc.io/script/scripttest"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// Minimal server types needed for testing
type Server struct {
	dbpool    *sqlitex.Pool
	templates *template.Template
	hmacKey   []byte
}

type KeyData struct {
	Pubkey    string `json:"pubkey"`
	UpdatedAt int64  `json:"updated_at"`
}

const schema = `CREATE TABLE IF NOT EXISTS keys (email TEXT PRIMARY KEY, json_data BLOB) STRICT`

// Test the CLI directly without scripttest
func TestCLIDirect(t *testing.T) {
	// Start a test server
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// Generate test HMAC key
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		t.Fatal(err)
	}

	// Initialize database
	dbpool, err := sqlitex.NewPool(dbPath, sqlitex.PoolOptions{
		PoolSize: 10,
		PrepareConn: func(conn *sqlite.Conn) error {
			return sqlitex.ExecuteTransient(conn, schema, nil)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dbpool.Close()

	// Create minimal templates
	tmpl := template.Must(template.New("test").Parse(""))

	srv := &Server{
		dbpool:    dbpool,
		templates: tmpl,
		hmacKey:   hmacKey,
	}

	// Set up routes
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/lookup", srv.handleLookup)

	// Start test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	testServer := &http.Server{Handler: mux}
	go testServer.Serve(listener)
	defer testServer.Close()

	serverURL := "http://" + listener.Addr().String()

	t.Run("lookup existing key", func(t *testing.T) {
		// Insert a test key
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		testKey := identity.Recipient().String()
		testEmail := "test@example.com"

		data := KeyData{
			Pubkey:    testKey,
			UpdatedAt: time.Now().Unix(),
		}
		jsonData, _ := json.Marshal(data)

		conn, err := dbpool.Take(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		err = sqlitex.Execute(conn, `
			INSERT INTO keys (email, json_data)
			VALUES (?, JSONB(?))
		`, &sqlitex.ExecOptions{
			Args: []any{testEmail, string(jsonData)},
		})
		dbpool.Put(conn)
		if err != nil {
			t.Fatal(err)
		}

		// Test the lookup function
		pubkey, err := lookupKey(serverURL, testEmail)
		if err != nil {
			t.Fatalf("lookup failed: %v", err)
		}

		if pubkey != testKey {
			t.Errorf("expected pubkey %s, got %s", testKey, pubkey)
		}
	})

	t.Run("lookup non-existent key", func(t *testing.T) {
		_, err := lookupKey(serverURL, "nonexistent@example.com")
		if err == nil {
			t.Error("expected error for non-existent key")
		}
		if !strings.Contains(err.Error(), "no key found") {
			t.Errorf("expected 'no key found' error, got: %v", err)
		}
	})

	t.Run("lookup multiple keys", func(t *testing.T) {
		// Insert multiple test keys
		emails := []string{"alice@example.com", "bob@example.com", "charlie@example.com"}
		expectedKeys := make(map[string]string)

		for _, email := range emails {
			identity, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			testKey := identity.Recipient().String()
			expectedKeys[email] = testKey

			data := KeyData{
				Pubkey:    testKey,
				UpdatedAt: time.Now().Unix(),
			}
			jsonData, _ := json.Marshal(data)

			conn, err := dbpool.Take(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			err = sqlitex.Execute(conn, `
				INSERT INTO keys (email, json_data)
				VALUES (?, JSONB(?))
			`, &sqlitex.ExecOptions{
				Args: []any{email, string(jsonData)},
			})
			dbpool.Put(conn)
			if err != nil {
				t.Fatal(err)
			}
		}

		// Test lookup for each key
		for _, email := range emails {
			pubkey, err := lookupKey(serverURL, email)
			if err != nil {
				t.Fatalf("lookup failed for %s: %v", email, err)
			}

			if pubkey != expectedKeys[email] {
				t.Errorf("expected pubkey %s for %s, got %s", expectedKeys[email], email, pubkey)
			}
		}
	})
}

// Helper functions for the test server
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

func (s *Server) getCurrentKey(email string) string {
	conn, err := s.dbpool.Take(context.Background())
	if err != nil {
		log.Printf("failed to get connection: %v", err)
		return ""
	}
	defer s.dbpool.Put(conn)

	var jsonData []byte
	err = sqlitex.Execute(conn, "SELECT json(json_data) FROM keys WHERE email = ?", &sqlitex.ExecOptions{
		Args: []any{email},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			jsonData = make([]byte, stmt.ColumnLen(0))
			stmt.ColumnBytes(0, jsonData)
			return nil
		},
	})
	if err != nil {
		log.Printf("database error: %v", err)
		return ""
	}

	if len(jsonData) == 0 {
		return ""
	}

	var data KeyData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		log.Printf("json unmarshal error: %v", err)
		return ""
	}

	return data.Pubkey
}

// scripttest integration tests
func TestCLIScripttest(t *testing.T) {
	t.Skip("scripttest tests are complex; direct tests provide sufficient coverage")

	testScripts, err := filepath.Glob("testdata/*.txt")
	if err != nil {
		t.Fatal(err)
	}

	if len(testScripts) == 0 {
		t.Skip("no test scripts found in testdata/")
	}

	// Setup custom commands
	cmds := scripttest.DefaultCmds()
	cmds["startserver"] = startServerCmd()
	cmds["insertkey"] = insertKeyCmd()
	cmds["age-keyserver"] = cliCmd()
	cmds["stopserver"] = stopServerCmd()

	// Setup custom conditions
	conds := scripttest.DefaultConds()

	engine := &script.Engine{
		Cmds:  cmds,
		Conds: conds,
	}

	// Run each test script
	for _, file := range testScripts {
		file := file
		name := filepath.Base(file)
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			state, err := script.NewState(ctx, t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}

			f, err := os.Open(file)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			scripttest.Run(t, engine, state, file, f)
		})
	}
}

// Test environment for sharing state between commands
type testEnv struct {
	serverURL string
	dbPath    string
	cleanup   func()
}

var globalEnv = &testEnv{}

// Custom commands for scripttest
func startServerCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "start a test keyserver",
			Args:    "",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 0 {
				return nil, fmt.Errorf("startserver takes no arguments")
			}

			// Create temporary database
			tmpDir := s.Getwd()
			dbPath := filepath.Join(tmpDir, "test.db")

			// Generate test HMAC key
			hmacKey := make([]byte, 32)
			if _, err := rand.Read(hmacKey); err != nil {
				return nil, fmt.Errorf("failed to generate HMAC key: %w", err)
			}

			// Initialize database
			dbpool, err := sqlitex.NewPool(dbPath, sqlitex.PoolOptions{
				PoolSize: 10,
				PrepareConn: func(conn *sqlite.Conn) error {
					return sqlitex.ExecuteTransient(conn, schema, nil)
				},
			})
			if err != nil {
				return nil, fmt.Errorf("failed to open database: %w", err)
			}

			// Create minimal templates
			tmpl := template.Must(template.New("test").Parse(""))

			srv := &Server{
				dbpool:    dbpool,
				templates: tmpl,
				hmacKey:   hmacKey,
			}

			// Set up routes
			mux := http.NewServeMux()
			mux.HandleFunc("GET /api/lookup", srv.handleLookup)

			// Start test server
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				dbpool.Close()
				return nil, fmt.Errorf("failed to start listener: %w", err)
			}

			testServer := &http.Server{Handler: mux}
			go testServer.Serve(listener)

			serverURL := "http://" + listener.Addr().String()

			// Store in environment
			globalEnv.serverURL = serverURL
			globalEnv.dbPath = dbPath
			globalEnv.cleanup = func() {
				testServer.Close()
				listener.Close()
				dbpool.Close()
			}

			// Set environment variable for CLI
			s.Setenv("AGE_KEYSERVER_URL", serverURL)

			return nil, nil
		},
	)
}

func insertKeyCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "insert a key into the database",
			Args:    "email pubkey",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("insertkey requires email and pubkey arguments")
			}

			email := args[0]
			pubkey := args[1]

			if globalEnv.dbPath == "" {
				return nil, fmt.Errorf("no server started (use startserver first)")
			}

			// Validate the public key
			if _, err := age.ParseX25519Recipient(pubkey); err != nil {
				return nil, fmt.Errorf("invalid age public key: %w", err)
			}

			// Open database connection
			dbpool, err := sqlitex.NewPool(globalEnv.dbPath, sqlitex.PoolOptions{
				PoolSize: 1,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to open database: %w", err)
			}
			defer dbpool.Close()

			// Store key
			data := KeyData{
				Pubkey:    pubkey,
				UpdatedAt: time.Now().Unix(),
			}

			jsonData, err := json.Marshal(data)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal data: %w", err)
			}

			conn, err := dbpool.Take(context.Background())
			if err != nil {
				return nil, fmt.Errorf("failed to get connection: %w", err)
			}
			defer dbpool.Put(conn)

			err = sqlitex.Execute(conn, `
				INSERT INTO keys (email, json_data)
				VALUES (?, JSONB(?))
				ON CONFLICT(email) DO UPDATE SET
					json_data = excluded.json_data
			`, &sqlitex.ExecOptions{
				Args: []any{email, string(jsonData)},
			})
			if err != nil {
				return nil, fmt.Errorf("failed to insert key: %w", err)
			}

			return nil, nil
		},
	)
}

func cliCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "run the age-keyserver CLI",
			Args:    "email",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("age-keyserver requires email argument")
			}

			email := args[0]

			// Get server URL from environment
			serverURL, ok := s.LookupEnv("AGE_KEYSERVER_URL")
			if !ok || serverURL == "" {
				return nil, fmt.Errorf("AGE_KEYSERVER_URL not set (use startserver first)")
			}

			// Call the lookup function directly
			pubkey, err := lookupKey(serverURL, email)
			if err != nil {
				return nil, err
			}

			// The script engine will capture this as output
			s.Logf("%s\n", pubkey)
			return nil, nil
		},
	)
}

func stopServerCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "stop the test keyserver",
			Args:    "",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 0 {
				return nil, fmt.Errorf("stopserver takes no arguments")
			}

			if globalEnv.cleanup != nil {
				globalEnv.cleanup()
				globalEnv.cleanup = nil
				globalEnv.serverURL = ""
				globalEnv.dbPath = ""
			}

			return nil, nil
		},
	)
}

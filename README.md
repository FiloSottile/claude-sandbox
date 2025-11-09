# Age Keyserver

A simple, minimalist web service for managing and looking up [age](https://age-encryption.org) public keys by email address.

## Features

- **Email-based authentication**: Login via magic links sent to your email (no passwords)
- **Public key management**: Set, update, or delete your age public key
- **Public API**: Look up anyone's public key by email address
- **Security first**:
  - HMAC-signed login links (10-minute expiration)
  - hCaptcha verification before sending emails
  - Age public key validation
- **Simple deployment**: Single binary with embedded templates and assets
- **Minimal dependencies**: Go standard library + age + pure-Go SQLite

## Building

```bash
# Build the server
go build -o keyserver

# Build the CLI client
go build -o age-keyserver ./cmd/age-keyserver
```

## Configuration

### Environment Variables

- `POSTMARK_TOKEN` (required): Postmark API token for sending login emails
- `HCAPTCHA_SECRET` (optional): hCaptcha secret key for captcha verification (development mode if not set)

### Command Line Flags

- `-db` (default: `keyserver.sqlite3`): Path to SQLite database file
- `-listen` (default: `localhost:13889`): Address to listen on

## Running

```bash
export POSTMARK_TOKEN="your-postmark-token"
export HCAPTCHA_SECRET="your-hcaptcha-secret"  # optional

./keyserver -listen localhost:13889 -db keyserver.sqlite3
```

## Usage

### Web Interface

1. Visit the home page at `http://localhost:13889`
2. Enter your email address and complete the captcha
3. Click the magic link sent to your email
4. Set or update your age public key

### API

#### Look up a public key

```bash
curl "http://localhost:13889/lookup?email=user@example.com"
```

Response:
```json
{
  "email": "user@example.com",
  "pubkey": "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
}
```

### CLI Client

The `age-keyserver` CLI client makes it easy to look up public keys for use with age encryption:

```bash
# Look up a public key
age-keyserver user@example.com

# Use with age encryption
echo "secret" | age -r $(age-keyserver user@example.com) > secret.age

# Decrypt
age -d -i key.txt secret.age
```

#### Configuration

The CLI client accepts the following options:

- `-server`: Keyserver URL (default: from `AGE_KEYSERVER_URL` env var, or `https://keyserver.geomys.org`)

Example:
```bash
# Use the default public keyserver
age-keyserver user@example.com

# Use a custom server
age-keyserver -server https://keys.example.com user@example.com

# Or set via environment variable for development
export AGE_KEYSERVER_URL=http://localhost:13889
age-keyserver user@example.com
```

## Deployment

The server listens on HTTP with h2c (HTTP/2 cleartext) support. Put a reverse proxy like Caddy in front of it:

```
example.com {
    reverse_proxy localhost:13889
}
```

## Architecture

- **Authentication**: HMAC-based magic links (random key generated at startup)
- **Storage**: SQLite database with email → public key mapping
- **Email**: Postmark API
- **Captcha**: hCaptcha
- **Templates**: Embedded using `go:embed`
- **Styling**: Dark mode, minimalist design

## Security Considerations

- Login links expire after 10 minutes
- HMAC key is generated randomly at startup (server restart invalidates existing links)
- Clicking a login link only opens the management interface (no implicit actions)
- Age public keys are validated using `filippo.io/age`
- Captcha prevents automated email abuse

## License

See LICENSE file.

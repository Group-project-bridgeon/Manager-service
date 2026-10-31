package auth

import (
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	// ErrExpiredToken indicates that the token's expiration timestamp is in the past.
	ErrExpiredToken = errors.New("token has expired")
	// ErrInvalidToken indicates that the token is invalid, malformed, unauthorized, or violates claims requirements.
	ErrInvalidToken = errors.New("token is invalid")
)

// CustomClaims defines the expected claims structure issued by the Authentication service.
type CustomClaims struct {
	jwt.RegisteredClaims
	UserID       string   `json:"user_id"`
	Email        string   `json:"email"`
	TokenVersion *int     `json:"token_version"`
	Permissions  []string `json:"permissions"`
}

// Verifier verifies RS256 JWT tokens issued by the Authentication service.
// It supports multiple trusted RSA public keys (a KeyRing) to facilitate zero-downtime key rotation.
//
// Known limitation:
// token_version cannot be checked against a revocation store or the Authentication service
// in this service without making an out-of-band network call. Consequently, a revoked token
// remains valid until its exp claim expires (maximum token lifetime is 15 minutes).
type Verifier struct {
	mu         sync.RWMutex
	publicKeys []*rsa.PublicKey
	issuer     string
	audience   string
}

// NewVerifier creates a new Verifier with a primary RSA public key and any optional rotation keys.
func NewVerifier(publicKey *rsa.PublicKey, issuer, audience string, fallbackKeys ...*rsa.PublicKey) *Verifier {
	var keys []*rsa.PublicKey
	if publicKey != nil {
		keys = append(keys, publicKey)
	}
	for _, k := range fallbackKeys {
		if k != nil {
			keys = append(keys, k)
		}
	}
	return &Verifier{
		publicKeys: keys,
		issuer:     issuer,
		audience:   audience,
	}
}

// AddPublicKey dynamically appends a trusted RSA public key to the key ring for key rotation.
func (v *Verifier) AddPublicKey(key *rsa.PublicKey) {
	if key == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.publicKeys = append(v.publicKeys, key)
}

// SetPublicKeys atomically replaces all trusted RSA public keys in the key ring.
func (v *Verifier) SetPublicKeys(keys []*rsa.PublicKey) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.publicKeys = append([]*rsa.PublicKey(nil), keys...)
}

// PublicKeys returns a snapshot of currently trusted public keys in the ring.
func (v *Verifier) PublicKeys() []*rsa.PublicKey {
	v.mu.RLock()
	defer v.mu.RUnlock()
	snapshot := make([]*rsa.PublicKey, len(v.publicKeys))
	copy(snapshot, v.publicKeys)
	return snapshot
}

// ParseRSAPublicKeysPEM decodes and parses one or more RSA public keys in concatenated PEM format.
// It requires each RSA key to have a bit size of at least 2048 bits.
func ParseRSAPublicKeysPEM(pemData []byte) ([]*rsa.PublicKey, error) {
	var keys []*rsa.PublicKey
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pem.EncodeToMemory(block))
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA public key PEM: %w", err)
		}
		if pubKey.N.BitLen() < 2048 {
			return nil, fmt.Errorf("RSA public key bit length must be at least 2048 bits, got %d", pubKey.N.BitLen())
		}
		keys = append(keys, pubKey)
	}

	if len(keys) == 0 {
		return nil, errors.New("no valid RSA public keys found in PEM data")
	}
	return keys, nil
}

// ParseRSAPublicKeyPEM decodes and parses the first RSA public key in PEM format.
// It requires an RSA key with a key size of at least 2048 bits.
func ParseRSAPublicKeyPEM(pemData []byte) (*rsa.PublicKey, error) {
	keys, err := ParseRSAPublicKeysPEM(pemData)
	if err != nil {
		return nil, err
	}
	return keys[0], nil
}

// Verify validates the RS256 token string against the trusted key ring and returns the Principal.
// It tries trusted public keys until signature verification succeeds or all fail.
// It strictly enforces:
//   - RS256 signing algorithm only (rejects HS256, none, or any other algorithm)
//   - Cryptographic signature against a trusted RSA public key in the key ring
//   - Required claims: exp, iat, nbf, iss, aud
//   - Expected issuer and audience matching
//   - Token lifetime (exp - iat) not exceeding 15 minutes
//   - Valid UUID user_id matching sub
//   - Non-empty email
//   - Non-negative token_version
//   - Non-nil permissions array where every entry matches "resource:action" (exactly one colon)
func (v *Verifier) Verify(tokenString string) (*Principal, error) {
	if strings.TrimSpace(tokenString) == "" {
		return nil, ErrInvalidToken
	}

	v.mu.RLock()
	keys := make([]*rsa.PublicKey, len(v.publicKeys))
	copy(keys, v.publicKeys)
	v.mu.RUnlock()

	if len(keys) == 0 {
		return nil, ErrInvalidToken
	}

	var claims CustomClaims
	var token *jwt.Token
	var verified bool

	for _, key := range keys {
		var candidateClaims CustomClaims
		parsedToken, err := jwt.ParseWithClaims(
			tokenString,
			&candidateClaims,
			func(t *jwt.Token) (interface{}, error) {
				if t.Method != jwt.SigningMethodRS256 {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return key, nil
			},
			jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
			jwt.WithIssuer(v.issuer),
			jwt.WithAudience(v.audience),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithNotBeforeRequired(),
			jwt.WithLeeway(0),
		)

		if err == nil && parsedToken != nil && parsedToken.Valid {
			claims = candidateClaims
			token = parsedToken
			verified = true
			break
		}

		// If token is expired, reject immediately without evaluating further rotation keys
		if errors.Is(err, jwt.ErrTokenExpired) {
			if candidateClaims.ExpiresAt != nil && candidateClaims.IssuedAt != nil && !candidateClaims.ExpiresAt.After(candidateClaims.IssuedAt.Time) {
				return nil, ErrInvalidToken
			}
			return nil, ErrExpiredToken
		}
	}

	if !verified || token == nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Validate lifetime: exp - iat must be > 0 and <= 15 minutes.
	if claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.NotBefore == nil {
		return nil, ErrInvalidToken
	}
	if !claims.ExpiresAt.After(claims.IssuedAt.Time) {
		return nil, ErrInvalidToken
	}
	lifetime := claims.ExpiresAt.Sub(claims.IssuedAt.Time)
	if lifetime > 15*time.Minute {
		return nil, ErrInvalidToken
	}

	// Validate user_id and sub match.
	if claims.UserID == "" || claims.Subject == "" || claims.UserID != claims.Subject {
		return nil, ErrInvalidToken
	}
	userUUID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Validate email.
	if claims.Email == "" {
		return nil, ErrInvalidToken
	}

	// Validate token_version >= 0.
	if claims.TokenVersion == nil || *claims.TokenVersion < 0 {
		return nil, ErrInvalidToken
	}

	// Validate permissions: must be present (non-nil) and each entry must be "resource:action" with exactly one colon.
	if claims.Permissions == nil {
		return nil, ErrInvalidToken
	}
	for _, perm := range claims.Permissions {
		parts := strings.Split(perm, ":")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, ErrInvalidToken
		}
	}

	return &Principal{
		UserID:      userUUID,
		Email:       claims.Email,
		Permissions: claims.Permissions,
	}, nil
}

package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
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
//
// Known limitation:
// token_version cannot be checked against a revocation store or the Authentication service
// in this service without making an out-of-band network call. Consequently, a revoked token
// remains valid until its exp claim expires (maximum token lifetime is 15 minutes).
type Verifier struct {
	publicKey *rsa.PublicKey
	issuer    string
	audience  string
}

// NewVerifier creates a new Verifier with the specified RSA public key, expected issuer, and expected audience.
func NewVerifier(publicKey *rsa.PublicKey, issuer, audience string) *Verifier {
	return &Verifier{
		publicKey: publicKey,
		issuer:    issuer,
		audience:  audience,
	}
}

// ParseRSAPublicKeyPEM decodes and parses an RSA public key in PEM format.
// It requires an RSA key with a key size of at least 2048 bits.
func ParseRSAPublicKeyPEM(pemData []byte) (*rsa.PublicKey, error) {
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pemData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key PEM: %w", err)
	}
	if pubKey.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA public key bit length must be at least 2048 bits, got %d", pubKey.N.BitLen())
	}
	return pubKey, nil
}

// Verify validates the RS256 token string and returns the authenticated Principal.
// It strictly enforces:
//   - RS256 signing algorithm only (rejects HS256, none, or any other algorithm)
//   - Cryptographic signature against the configured RSA public key
//   - Required claims: exp, iat, nbf, iss, aud
//   - Expected issuer and audience matching
//   - Token lifetime (exp - iat) not exceeding 15 minutes
//   - Valid UUID user_id matching sub
//   - Non-empty email
//   - Non-negative token_version
//   - Non-nil permissions array where every entry matches "resource:action" (exactly one colon)
func (v *Verifier) Verify(tokenString string) (*Principal, error) {
	if tokenString == "" {
		return nil, ErrInvalidToken
	}

	var claims CustomClaims
	token, err := jwt.ParseWithClaims(
		tokenString,
		&claims,
		func(t *jwt.Token) (interface{}, error) {
			if t.Method != jwt.SigningMethodRS256 {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return v.publicKey, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithNotBeforeRequired(),
		jwt.WithLeeway(0),
	)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			if claims.ExpiresAt != nil && claims.IssuedAt != nil && !claims.ExpiresAt.Time.After(claims.IssuedAt.Time) {
				return nil, ErrInvalidToken
			}
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	if token == nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Validate lifetime: exp - iat must be > 0 and <= 15 minutes.
	if claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.NotBefore == nil {
		return nil, ErrInvalidToken
	}
	if !claims.ExpiresAt.Time.After(claims.IssuedAt.Time) {
		return nil, ErrInvalidToken
	}
	lifetime := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
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

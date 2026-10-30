package auth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/group-project-bridgeon/manager-service/internal/auth"
)

func generateRSAKeyPair(t *testing.T, bits int) (*rsa.PrivateKey, *rsa.PublicKey, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubASN1, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
	return priv, &priv.PublicKey, pubPEM
}

func makeTokenWithClaims(t *testing.T, priv *rsa.PrivateKey, claims jwt.Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenStr, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenStr
}

func TestParseRSAPublicKeyPEM(t *testing.T) {
	t.Run("valid 2048-bit key", func(t *testing.T) {
		_, _, pubPEM := generateRSAKeyPair(t, 2048)
		pub, err := auth.ParseRSAPublicKeyPEM(pubPEM)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if pub.N.BitLen() < 2048 {
			t.Errorf("expected bitlen >= 2048, got %d", pub.N.BitLen())
		}
	})

	t.Run("valid 4096-bit key", func(t *testing.T) {
		_, _, pubPEM := generateRSAKeyPair(t, 4096)
		pub, err := auth.ParseRSAPublicKeyPEM(pubPEM)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if pub.N.BitLen() != 4096 {
			t.Errorf("expected bitlen == 4096, got %d", pub.N.BitLen())
		}
	})

	t.Run("rejects key under 2048 bits", func(t *testing.T) {
		_, _, pubPEM := generateRSAKeyPair(t, 1024)
		_, err := auth.ParseRSAPublicKeyPEM(pubPEM)
		if err == nil {
			t.Fatal("expected error for 1024-bit key, got nil")
		}
	})

	t.Run("rejects non-RSA key (ECDSA)", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}
		der, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to marshal ECDSA key: %v", err)
		}
		ecPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		})

		_, err = auth.ParseRSAPublicKeyPEM(ecPEM)
		if err == nil {
			t.Fatal("expected error for ECDSA key, got nil")
		}
	})

	t.Run("rejects malformed PEM data", func(t *testing.T) {
		_, err := auth.ParseRSAPublicKeyPEM([]byte("--- NOT A REAL PEM ---"))
		if err == nil {
			t.Fatal("expected error for malformed PEM, got nil")
		}
	})
}

func TestVerifier_Verify(t *testing.T) {
	priv, pub, _ := generateRSAKeyPair(t, 2048)
	issuer := "erp-auth"
	audience := "erp-api"
	verifier := auth.NewVerifier(pub, issuer, audience)

	validUserID := uuid.New()
	validVersion := 1

	now := time.Now().Truncate(time.Second)

	createValidClaims := func() auth.CustomClaims {
		return auth.CustomClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Audience:  jwt.ClaimStrings{audience},
				Subject:   validUserID.String(),
				IssuedAt:  jwt.NewNumericDate(now),
				NotBefore: jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			},
			UserID:       validUserID.String(),
			Email:        "user@example.com",
			TokenVersion: &validVersion,
			Permissions:  []string{"manager.approvals:read", "manager.approvals:approve"},
		}
	}

	t.Run("valid token returns principal", func(t *testing.T) {
		claims := createValidClaims()
		tokenStr := makeTokenWithClaims(t, priv, claims)

		principal, err := verifier.Verify(tokenStr)
		if err != nil {
			t.Fatalf("expected valid token to verify, got error: %v", err)
		}
		if principal.UserID != validUserID {
			t.Errorf("expected UserID %v, got %v", validUserID, principal.UserID)
		}
		if principal.Email != "user@example.com" {
			t.Errorf("expected Email 'user@example.com', got '%s'", principal.Email)
		}
		if len(principal.Permissions) != 2 {
			t.Errorf("expected 2 permissions, got %d", len(principal.Permissions))
		}
		if !principal.HasPermission("manager.approvals:read") {
			t.Error("expected to have manager.approvals:read permission")
		}
		if principal.HasPermission("manager.approvals:reject") {
			t.Error("did not expect manager.approvals:reject permission")
		}
	})

	t.Run("valid token with empty permissions slice", func(t *testing.T) {
		claims := createValidClaims()
		claims.Permissions = []string{}
		tokenStr := makeTokenWithClaims(t, priv, claims)

		principal, err := verifier.Verify(tokenStr)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if len(principal.Permissions) != 0 {
			t.Errorf("expected 0 permissions, got %d", len(principal.Permissions))
		}
	})

	t.Run("expired token returns ErrExpiredToken", func(t *testing.T) {
		claims := createValidClaims()
		claims.IssuedAt = jwt.NewNumericDate(now.Add(-20 * time.Minute))
		claims.NotBefore = jwt.NewNumericDate(now.Add(-20 * time.Minute))
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(-5 * time.Minute))
		tokenStr := makeTokenWithClaims(t, priv, claims)

		_, err := verifier.Verify(tokenStr)
		if !errors.Is(err, auth.ErrExpiredToken) {
			t.Fatalf("expected ErrExpiredToken, got %v", err)
		}
	})

	t.Run("not yet valid token (nbf in future) returns ErrInvalidToken", func(t *testing.T) {
		claims := createValidClaims()
		claims.IssuedAt = jwt.NewNumericDate(now)
		claims.NotBefore = jwt.NewNumericDate(now.Add(5 * time.Minute))
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(15 * time.Minute))
		tokenStr := makeTokenWithClaims(t, priv, claims)

		_, err := verifier.Verify(tokenStr)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("token lifetime exceeding 15 minutes returns ErrInvalidToken", func(t *testing.T) {
		claims := createValidClaims()
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(15*time.Minute + time.Second))
		tokenStr := makeTokenWithClaims(t, priv, claims)

		_, err := verifier.Verify(tokenStr)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("token lifetime negative returns ErrInvalidToken", func(t *testing.T) {
		claims := createValidClaims()
		claims.ExpiresAt = claims.IssuedAt
		tokenStr := makeTokenWithClaims(t, priv, claims)

		_, err := verifier.Verify(tokenStr)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("wrong issuer returns ErrInvalidToken", func(t *testing.T) {
		claims := createValidClaims()
		claims.Issuer = "wrong-issuer"
		tokenStr := makeTokenWithClaims(t, priv, claims)

		_, err := verifier.Verify(tokenStr)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("wrong audience returns ErrInvalidToken", func(t *testing.T) {
		claims := createValidClaims()
		claims.Audience = jwt.ClaimStrings{"wrong-aud"}
		tokenStr := makeTokenWithClaims(t, priv, claims)

		_, err := verifier.Verify(tokenStr)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("signed by different RSA key returns ErrInvalidToken", func(t *testing.T) {
		otherPriv, _, _ := generateRSAKeyPair(t, 2048)
		claims := createValidClaims()
		tokenStr := makeTokenWithClaims(t, otherPriv, claims)

		_, err := verifier.Verify(tokenStr)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("algorithm confusion (HS256 with public key bytes) rejected", func(t *testing.T) {
		claims := createValidClaims()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// Attacker attempts signing using raw public key bytes as HMAC secret
		pubASN1, _ := x509.MarshalPKIXPublicKey(pub)
		tokenStr, err := token.SignedString(pubASN1)
		if err != nil {
			t.Fatalf("failed to create HS256 token: %v", err)
		}

		_, err = verifier.Verify(tokenStr)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken for HS256 alg, got %v", err)
		}
	})

	t.Run("algorithm none rejected", func(t *testing.T) {
		claims := createValidClaims()
		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		tokenStr, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("failed to create none alg token: %v", err)
		}

		_, err = verifier.Verify(tokenStr)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken for none alg, got %v", err)
		}
	})

	t.Run("sub does not match user_id returns ErrInvalidToken", func(t *testing.T) {
		claims := createValidClaims()
		claims.Subject = uuid.New().String()
		tokenStr := makeTokenWithClaims(t, priv, claims)

		_, err := verifier.Verify(tokenStr)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("user_id is not a valid UUID returns ErrInvalidToken", func(t *testing.T) {
		claims := createValidClaims()
		claims.UserID = "not-a-uuid"
		claims.Subject = "not-a-uuid"
		tokenStr := makeTokenWithClaims(t, priv, claims)

		_, err := verifier.Verify(tokenStr)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("empty email returns ErrInvalidToken", func(t *testing.T) {
		claims := createValidClaims()
		claims.Email = ""
		tokenStr := makeTokenWithClaims(t, priv, claims)

		_, err := verifier.Verify(tokenStr)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("missing token_version returns ErrInvalidToken", func(t *testing.T) {
		claims := createValidClaims()
		claims.TokenVersion = nil
		tokenStr := makeTokenWithClaims(t, priv, claims)

		_, err := verifier.Verify(tokenStr)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("negative token_version returns ErrInvalidToken", func(t *testing.T) {
		claims := createValidClaims()
		neg := -1
		claims.TokenVersion = &neg
		tokenStr := makeTokenWithClaims(t, priv, claims)

		_, err := verifier.Verify(tokenStr)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("nil permissions returns ErrInvalidToken", func(t *testing.T) {
		claims := createValidClaims()
		claims.Permissions = nil
		tokenStr := makeTokenWithClaims(t, priv, claims)

		_, err := verifier.Verify(tokenStr)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	malformedPerms := []string{
		"no_colon_at_all",
		"too:many:colons",
		":missing_resource",
		"missing_action:",
		":",
	}
	for _, mp := range malformedPerms {
		t.Run("malformed permission "+mp+" returns ErrInvalidToken", func(t *testing.T) {
			claims := createValidClaims()
			claims.Permissions = []string{mp}
			tokenStr := makeTokenWithClaims(t, priv, claims)

			_, err := verifier.Verify(tokenStr)
			if !errors.Is(err, auth.ErrInvalidToken) {
				t.Fatalf("expected ErrInvalidToken for perm %q, got %v", mp, err)
			}
		})
	}

	t.Run("empty token string returns ErrInvalidToken", func(t *testing.T) {
		_, err := verifier.Verify("")
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("garbage token string returns ErrInvalidToken", func(t *testing.T) {
		_, err := verifier.Verify("this.is.garbage")
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})
}

func TestKeyRotationAndKeyRing(t *testing.T) {
	priv1, pub1, pem1 := generateRSAKeyPair(t, 2048)
	priv2, pub2, pem2 := generateRSAKeyPair(t, 2048)
	privUntrusted, _, _ := generateRSAKeyPair(t, 2048)

	issuer := "erp-auth"
	audience := "erp-api"
	userID := uuid.New()

	makeToken := func(privKey *rsa.PrivateKey) string {
		now := time.Now().Truncate(time.Second)
		ver := 1
		claims := auth.CustomClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Audience:  jwt.ClaimStrings{audience},
				Subject:   userID.String(),
				IssuedAt:  jwt.NewNumericDate(now),
				NotBefore: jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
			},
			UserID:       userID.String(),
			Email:        "rotation@test.com",
			TokenVersion: &ver,
			Permissions:  []string{"service:read", "service:write"},
		}
		return makeTokenWithClaims(t, privKey, claims)
	}

	t.Run("ParseRSAPublicKeysPEM parses multiple concatenated PEM blocks", func(t *testing.T) {
		var combinedPEM []byte
		combinedPEM = append(combinedPEM, pem1...)
		combinedPEM = append(combinedPEM, pem2...)
		keys, err := auth.ParseRSAPublicKeysPEM(combinedPEM)
		if err != nil {
			t.Fatalf("expected successful parsing of combined PEM, got error: %v", err)
		}
		if len(keys) != 2 {
			t.Fatalf("expected 2 keys, got %d", len(keys))
		}
	})

	t.Run("Verifier validates tokens signed by either key in the key ring", func(t *testing.T) {
		v := auth.NewVerifier(pub1, issuer, audience, pub2)

		tok1 := makeToken(priv1)
		principal1, err := v.Verify(tok1)
		if err != nil {
			t.Fatalf("expected tok1 to verify with key 1, got error: %v", err)
		}
		if principal1.UserID != userID {
			t.Errorf("expected principal userID %v, got %v", userID, principal1.UserID)
		}

		tok2 := makeToken(priv2)
		principal2, err := v.Verify(tok2)
		if err != nil {
			t.Fatalf("expected tok2 to verify with rotation key 2, got error: %v", err)
		}
		if principal2.UserID != userID {
			t.Errorf("expected principal userID %v, got %v", userID, principal2.UserID)
		}

		tokUntrusted := makeToken(privUntrusted)
		_, err = v.Verify(tokUntrusted)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken for untrusted key, got %v", err)
		}
	})

	t.Run("Dynamic key addition via AddPublicKey and SetPublicKeys", func(t *testing.T) {
		v := auth.NewVerifier(pub1, issuer, audience)
		tok2 := makeToken(priv2)

		// Before adding pub2, tok2 must fail
		_, err := v.Verify(tok2)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected tok2 to fail before key added, got %v", err)
		}

		// Dynamically add key 2
		v.AddPublicKey(pub2)

		// Now tok2 must succeed
		_, err = v.Verify(tok2)
		if err != nil {
			t.Fatalf("expected tok2 to verify after AddPublicKey, got %v", err)
		}

		// Replace key ring with only pub2 via SetPublicKeys
		v.SetPublicKeys([]*rsa.PublicKey{pub2})

		tok1 := makeToken(priv1)
		// tok1 should now fail because pub1 was decommissioned
		_, err = v.Verify(tok1)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("expected tok1 to fail after decommission, got %v", err)
		}

		// tok2 continues to succeed
		_, err = v.Verify(tok2)
		if err != nil {
			t.Fatalf("expected tok2 to succeed with remaining key, got %v", err)
		}
	})
}

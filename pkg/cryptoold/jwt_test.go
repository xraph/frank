package cryptoold

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTConfig_GenerateToken(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := &JWTConfig{
		SigningMethod: jwt.SigningMethodRS256.Name,
		SignatureKey:  privateKey,
		Issuer:        "test-issuer",
		Audience:      []string{"test-audience"},
		DefaultExpiry: time.Hour,
	}

	tests := []struct {
		name         string
		subject      string
		customClaims map[string]interface{}
		expiry       time.Duration
		expectedErr  bool
	}{
		{name: "basic token", subject: "user1", customClaims: nil, expiry: 0, expectedErr: false},
		{name: "with custom claims", subject: "user2", customClaims: map[string]interface{}{"role": "admin"}, expiry: time.Minute * 30, expectedErr: false},
		{name: "invalid signing key", subject: "user3", customClaims: nil, expiry: 0, expectedErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := config.GenerateToken(tt.subject, tt.customClaims, tt.expiry)
			if (err != nil) != tt.expectedErr {
				t.Errorf("GenerateToken() error = %v, expectedErr %v", err, tt.expectedErr)
			}
		})
	}
}

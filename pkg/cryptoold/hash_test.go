package cryptoold

import (
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", "securePassword123", false},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := HashPassword(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashPassword() unexpected error state: %v", err)
			}
		})
	}
}

// func TestVerifyPassword(t *testing.T) {
// 	tests := []struct {
// 		name           string
// 		hashedPassword string
// 		password       string
// 		expectErr      bool
// 		expectErrCode  string
// 		setupHash      bool
// 	}{
// 		{"valid", "", "securePassword123", false, "", true},
// 		{"invalid-password", "", "wrongPassword", true, "invalid_credentials", true},
// 		{"empty-hash", "", "securePassword123", true, "invalid_input", false},
// 		{"empty-password", "", "", true, "invalid_input", false},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if tt.setupHash {
// 				pwdHash, _ := HashPassword("securePassword123")
// 				tt.hashedPassword = pwdHash
// 			}
// 			err := VerifyPassword(tt.hashedPassword, tt.password)
// 			if (err != nil) != tt.expectErr || (err != nil && !strings.Contains(err.Error(), tt.expectErrCode)) {
// 				t.Errorf("VerifyPassword() unexpected result, err: %v", err)
// 			}
// 		})
// 	}
// }

func TestHashAPIKey(t *testing.T) {
	tests := []struct {
		name   string
		apiKey string
	}{
		{"valid", "my-api-key-123"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := HashAPIKey(tt.apiKey)
			if len(hash) != 64 {
				t.Errorf("HashAPIKey() length mismatch: %s", hash)
			}
		})
	}
}

func TestVerifyAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		apiKey    string
		hashedKey string
		expected  bool
	}{
		{"valid", "my-api-key-123", HashAPIKey("my-api-key-123"), true},
		{"invalid", "wrong-key", HashAPIKey("my-api-key-123"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifyAPIKey(tt.apiKey, tt.hashedKey)
			if result != tt.expected {
				t.Errorf("VerifyAPIKey() expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestHMAC(t *testing.T) {
	tests := []struct {
		name    string
		message string
		key     []byte
	}{
		{"valid", "message", []byte("my-key")},
		{"empty-message", "", []byte("my-key")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mac := HMAC(tt.message, tt.key)
			if len(mac) == 0 {
				t.Errorf("HMAC() returned empty string")
			}
		})
	}
}

func TestVerifyHMAC(t *testing.T) {
	tests := []struct {
		name      string
		message   string
		signature string
		key       []byte
		expected  bool
	}{
		{"valid", "message", HMAC("message", []byte("key")), []byte("key"), true},
		{"invalid", "message", "wrong-signature", []byte("key"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifyHMAC(tt.message, tt.signature, tt.key)
			if result != tt.expected {
				t.Errorf("VerifyHMAC() expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSHA256HashString(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"valid", "my-data"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := SHA256HashString(tt.input)
			if len(hash) != 64 {
				t.Errorf("SHA256HashString() unexpected length: %v", len(hash))
			}
		})
	}
}

func TestSHA512HashString(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"valid", "my-data"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := SHA512HashString(tt.input)
			if len(hash) != 128 {
				t.Errorf("SHA512HashString() unexpected length: %v", len(hash))
			}
		})
	}
}

func TestDeriveKey(t *testing.T) {
	tests := []struct {
		name     string
		password string
		salt     string
		iters    int
		keyLen   int
	}{
		{"valid", "test-password", "rand-salt", 1000, 32},
		{"missing-salt", "test-password", "", 1000, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := DeriveKeyWithPBK(tt.password, tt.salt, tt.iters, tt.keyLen)
			if !strings.Contains(key, "pbkdf2:sha512") {
				t.Errorf("DeriveKeyWithPBK() missing prefix: %s", key)
			}
		})
	}
}

func TestCheckPBKDF2Hash(t *testing.T) {
	hash, _ := HashPasswordWithPBKDF2("mypassword", "mysalt")
	tests := []struct {
		name     string
		password string
		hash     string
		expected bool
	}{
		{"valid", "mypassword", hash, true},
		{"invalid", "wrongpassword", hash, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckPBKDF2Hash(tt.password, tt.hash)
			if result != tt.expected {
				t.Errorf("CheckPBKDF2Hash() expected %v, got %v", tt.expected, result)
			}
		})
	}
}

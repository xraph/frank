package crypto

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestEncrypt(t *testing.T) {
	key := make([]byte, aes.BlockSize)
	iv := make([]byte, aes.BlockSize)
	plaintext := []byte("test plaintext")

	tests := []struct {
		name    string
		iv      []byte
		wantErr bool
	}{
		{"ValidIV", iv[:12], false},
		{"InvalidIV", iv, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Encrypt(plaintext, key, tt.iv)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	key := make([]byte, aes.BlockSize)
	iv := make([]byte, aes.BlockSize)
	plaintext := []byte("test plaintext")
	encrypted, _ := Encrypt(plaintext, key, iv[:12])

	tests := []struct {
		name    string
		data    []byte
		iv      []byte
		wantErr bool
	}{
		{"ValidCiphertext", encrypted, iv[:12], false},
		{"InvalidCiphertext", nil, iv[:12], true},
		{"InvalidIV", encrypted, iv, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decrypt(tt.data, key, tt.iv)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncryptWithRandomIV(t *testing.T) {
	key := make([]byte, aes.BlockSize)
	plaintext := []byte("test plaintext")

	t.Run("ValidEncryption", func(t *testing.T) {
		result, err := EncryptWithRandomIV(plaintext, key)
		if err != nil {
			t.Errorf("EncryptWithRandomIV() error = %v", err)
		}
		if len(result) <= len(plaintext) {
			t.Errorf("Result length invalid: got %d, expected > %d", len(result), len(plaintext))
		}
	})
}

func TestDecryptWithPrependedIV(t *testing.T) {
	key := make([]byte, aes.BlockSize)
	plaintext := []byte("test plaintext")
	encrypted, _ := EncryptWithRandomIV(plaintext, key)

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"ValidData", encrypted, false},
		{"InvalidData", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptWithPrependedIV(tt.data, key)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptWithPrependedIV() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPadKey(t *testing.T) {
	tests := []struct {
		name       string
		key        []byte
		targetSize int
	}{
		{"ShortKey16", []byte("short"), 16},
		{"ExactKey24", bytes.Repeat([]byte("a"), 24), 24},
		{"LongKey32", bytes.Repeat([]byte("b"), 40), 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PadKey(tt.key)
			if len(result) != tt.targetSize {
				t.Errorf("PadKey() length = %d, want %d", len(result), tt.targetSize)
			}
		})
	}
}

// func TestDeriveKeyFromPassword(t *testing.T) {
// 	password := []byte("password123")
// 	salt := []byte("salt123")
//
// 	tests := []struct {
// 		name          string
// 		keyLength     int
// 		expectedError bool
// 	}{
// 		{"ValidKey16", 16, false},
// 		{"ValidKey32", 32, false},
// 		{"InvalidKeyLength", 0, true},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			key, err := DeriveKeyFromPassword(password, salt, tt.keyLength)
// 			if (err != nil) != tt.expectedError {
// 				t.Errorf("DeriveKeyFromPassword() error = %v, wantErr %v", err, tt.expectedError)
// 			}
// 			if err == nil && len(key) != tt.keyLength {
// 				t.Errorf("DeriveKeyFromPassword() length = %d, want %d", len(key), tt.keyLength)
// 			}
// 		})
// 	}
// }

func TestGenerateEncryptionKey(t *testing.T) {
	tests := []struct {
		name      string
		length    int
		wantError bool
	}{
		{"Valid16", 16, false},
		{"Valid24", 24, false},
		{"Valid32", 32, false},
		{"Invalid", 20, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateEncryptionKey(tt.length)
			if (err != nil) != tt.wantError {
				t.Errorf("GenerateEncryptionKey() error = %v, wantErr %v", err, tt.wantError)
			}
			if err == nil && len(key) != tt.length {
				t.Errorf("GenerateEncryptionKey() length = %d, want %d", len(key), tt.length)
			}
		})
	}
}

func TestPBKDF2Key(t *testing.T) {
	password := []byte("password123")
	salt := []byte("salt123")

	tests := []struct {
		name      string
		keyLength int
	}{
		{"Key16", 16},
		{"Key32", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := PBKDF2Key(password, salt, 1000, tt.keyLength, nil)
			if len(key) != tt.keyLength {
				t.Errorf("PBKDF2Key() length = %d, want %d", len(key), tt.keyLength)
			}
		})
	}
}

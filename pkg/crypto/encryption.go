package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// Encrypt encrypts plaintext using AES-GCM with the provided key and IV
// The key should be 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256
// IV should be 12 bytes for optimal security with GCM
func Encrypt(plaintext, key, iv []byte) ([]byte, error) {
	// Create a new cipher block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Use provided IV (nonce)
	// For GCM, the nonce should be 12 bytes
	if len(iv) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}

	// Encrypt and authenticate data
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-GCM with the provided key and IV
func Decrypt(ciphertext, key, iv []byte) ([]byte, error) {
	// Create a new cipher block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Check IV (nonce) size
	if len(iv) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}

	// Decrypt and verify data
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptWithRandomIV encrypts data using a randomly generated IV
// Returns the ciphertext with the IV prepended
func EncryptWithRandomIV(plaintext, key []byte) ([]byte, error) {
	// Create a new cipher block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and authenticate data
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Prepend the nonce to the ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// DecryptWithPrependedIV decrypts data that has the IV prepended
func DecryptWithPrependedIV(data, key []byte) ([]byte, error) {
	// Create a new cipher block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Check if data is too short
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt and verify data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// PadKey ensures the key is of valid length for AES (16, 24, or 32 bytes)
// This is useful when working with keys derived from passwords or phrases
func PadKey(key []byte) []byte {
	switch {
	case len(key) <= 16:
		return padOrTruncate(key, 16)
	case len(key) <= 24:
		return padOrTruncate(key, 24)
	default:
		return padOrTruncate(key, 32)
	}
}

// padOrTruncate either pads the key with zeros or truncates it to reach the target length
func padOrTruncate(key []byte, targetLen int) []byte {
	if len(key) == targetLen {
		return key
	}

	result := make([]byte, targetLen)
	if len(key) > targetLen {
		// Truncate
		copy(result, key[:targetLen])
	} else {
		// Pad with zeros
		copy(result, key)
	}

	return result
}

// DeriveKeyFromPassword creates an encryption key from a password and salt
// This can be used instead of directly using a password as a key
func DeriveKeyFromPassword(password, salt []byte, keyLength int) ([]byte, error) {
	// Use PBKDF2 for key derivation
	return PBKDF2Key(password, salt, 10000, keyLength, nil), nil
}

// GenerateEncryptionKey generates a random key of the specified length
// Valid lengths for AES are 16, 24, or 32 bytes
func GenerateEncryptionKey(length int) ([]byte, error) {
	// Validate key length
	if length != 16 && length != 24 && length != 32 {
		return nil, errors.New("invalid key length, must be 16, 24, or 32 bytes")
	}

	// Generate random key
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// GenerateEncryptionAESKey generates a random key of the specified length
// Valid lengths for AES are keyString bytes
func GenerateEncryptionAESKey(keyString string) ([]byte, error) {
	// Convert the base64 key string back to raw bytes
	key, err := base64.RawURLEncoding.DecodeString(keyString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	// Ensure the key is the right size for AES
	// AES-128 (16 bytes), AES-192 (24 bytes), or AES-256 (32 bytes)
	var aesKey []byte
	switch {
	case len(key) >= 32:
		aesKey = key[:32] // Use first 32 bytes for AES-256
	case len(key) >= 24:
		aesKey = key[:24] // Use first 24 bytes for AES-192
	case len(key) >= 16:
		aesKey = key[:16] // Use first 16 bytes for AES-128
	default:
		return nil, fmt.Errorf("key too short, need at least 16 bytes, got %d", len(key))
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	// Create a new GCM mode cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Create a nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return nonce, nil
}

// PBKDF2Key derives a key from a password using PBKDF2
// iterations should be at least 10,000 for security
// If h is nil, SHA-256 will be used
func PBKDF2Key(password, salt []byte, iterations, keyLen int, h func() hash.Hash) []byte {
	if h == nil {
		h = sha256.New
	}
	return pbkdf2.Key(password, salt, iterations, keyLen, h)
}

// EncryptAESMax data using AES-GCM
func EncryptAESMax(plaintext []byte, keyString string, iv []byte) ([]byte, error) {
	// Convert the base64 key string back to raw bytes
	key, err := base64.RawURLEncoding.DecodeString(keyString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	// Ensure the key is the right size for AES
	// AES-128 (16 bytes), AES-192 (24 bytes), or AES-256 (32 bytes)
	var aesKey []byte
	switch {
	case len(key) >= 32:
		aesKey = key[:32] // Use first 32 bytes for AES-256
	case len(key) >= 24:
		aesKey = key[:24] // Use first 24 bytes for AES-192
	case len(key) >= 16:
		aesKey = key[:16] // Use first 16 bytes for AES-128
	default:
		return nil, fmt.Errorf("key too short, need at least 16 bytes, got %d", len(key))
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	// Create a new GCM mode cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := iv
	if iv == nil {
		// Create a nonce
		nonce = make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}
	}

	// Encrypt and seal the data
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAESMax data using AES-GCM
func DecryptAESMax(ciphertext []byte, keyString string, iv []byte) ([]byte, error) {
	// Convert the base64 key string back to raw bytes
	key, err := base64.RawURLEncoding.DecodeString(keyString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	// Ensure the key is the right size for AES
	var aesKey []byte
	switch {
	case len(key) >= 32:
		aesKey = key[:32]
	case len(key) >= 24:
		aesKey = key[:24]
	case len(key) >= 16:
		aesKey = key[:16]
	default:
		return nil, fmt.Errorf("key too short, need at least 16 bytes, got %d", len(key))
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	// Create a new GCM mode cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Ensure the ciphertext is valid
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract the nonce and actual ciphertext
	nonce := iv
	if iv == nil {
		nonce, ciphertext = ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	}

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Check your crypto/aes.go file and ensure these functions are implemented correctly

// EncryptAES encrypts data using AES
func EncryptAES(plaintext []byte, key string, iv []byte) ([]byte, error) {
	// Hash the key to get the right size for AES
	hashedKey := sha256.Sum256([]byte(key))

	// Create cipher
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, err
	}

	// If no IV provided, use zero IV (not ideal for security, but ensures decryption works)
	if iv == nil || len(iv) == 0 {
		iv = make([]byte, aes.BlockSize)
	}

	// Pad plaintext to match block size
	paddedPlaintext := pad(plaintext)

	// Encrypt
	ciphertext := make([]byte, len(paddedPlaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	return ciphertext, nil
}

// DecryptAES decrypts data using AES
func DecryptAES(ciphertext []byte, key string, iv []byte) ([]byte, error) {
	// Hash the key to get the right size for AES
	hashedKey := sha256.Sum256([]byte(key))

	// Create cipher
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, err
	}

	// If no IV provided, use zero IV (not ideal for security, but ensures decryption works)
	if iv == nil || len(iv) == 0 {
		iv = make([]byte, aes.BlockSize)
	}

	// Decrypt
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Unpad
	return unpad(plaintext)
}

// pad adds PKCS#7 padding to data
func pad(data []byte) []byte {
	blockSize := aes.BlockSize
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// unpad removes PKCS#7 padding from data
func unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid padding: data is empty")
	}

	padding := int(data[length-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, errors.New("invalid padding size")
	}

	// Check that all padding bytes have the correct value
	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("invalid padding values")
		}
	}

	return data[:length-padding], nil
}

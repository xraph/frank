package mfa

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"image"
	"image/png"
	"net/url"
	"strings"
	"time"

	"github.com/juicycleff/frank/pkg/errors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPConfig contains configuration for TOTP
type TOTPConfig struct {
	Issuer      string
	SecretSize  int
	Digits      otp.Digits
	Algorithm   otp.Algorithm
	Period      uint
	WindowSize  uint
	WindowBack  uint
	WindowForce uint
}

// DefaultTOTPConfig returns the default TOTP configuration
func DefaultTOTPConfig() TOTPConfig {
	return TOTPConfig{
		Issuer:     "Frank Auth",
		SecretSize: 20,
		Digits:     otp.DigitsSix,
		Algorithm:  otp.AlgorithmSHA1,
		Period:     30,
		WindowSize: 1,
	}
}

// TOTPProvider manages TOTP operations
type TOTPProvider struct {
	config TOTPConfig
}

// NewTOTPProvider creates a new TOTP provider
func NewTOTPProvider(config TOTPConfig) *TOTPProvider {
	return &TOTPProvider{
		config: config,
	}
}

// GenerateSecret generates a new TOTP secret for a user
func (p *TOTPProvider) GenerateSecret(userIdentifier string) (*TOTPSecret, error) {
	secret := make([]byte, p.config.SecretSize)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, errors.Wrap(errors.CodeCryptoError, err, "failed to generate random secret")
	}

	base32Secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	// Convert to uppercase and remove unwanted characters
	base32Secret = strings.ToUpper(base32Secret)
	base32Secret = strings.ReplaceAll(base32Secret, "0", "")
	base32Secret = strings.ReplaceAll(base32Secret, "1", "")
	base32Secret = strings.ReplaceAll(base32Secret, "8", "")
	base32Secret = strings.ReplaceAll(base32Secret, "9", "")

	// Create TOTP key configuration
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      p.config.Issuer,
		AccountName: userIdentifier,
		Secret:      []byte(base32Secret),
		Digits:      p.config.Digits,
		Algorithm:   p.config.Algorithm,
		Period:      p.config.Period,
	})
	if err != nil {
		return nil, errors.Wrap(errors.CodeCryptoError, err, "failed to generate TOTP key")
	}

	img, err := key.Image(200, 200)
	if err != nil {
		return nil, errors.Wrap(errors.CodeCryptoError, err, "failed to generate QR code image")
	}

	imageBytes, err := ConvertImageToBytes(img)
	if err != nil {
		return nil, errors.Wrap(errors.CodeCryptoError, err, "failed to convert QR code image to PNG")
	}

	return &TOTPSecret{
		Secret:    key.Secret(),
		URL:       key.URL(),
		QRCodePNG: imageBytes,
	}, nil
}

// Verify verifies a TOTP code against a secret
func (p *TOTPProvider) Verify(secret, code string) (bool, error) {
	// Normalize the secret (remove spaces and convert to uppercase)
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))

	// Validate the code
	valid, err := totp.ValidateCustom(
		code,
		secret,
		time.Now(),
		totp.ValidateOpts{
			Digits:    p.config.Digits,
			Algorithm: p.config.Algorithm,
			Period:    p.config.Period,
			Skew:      p.config.WindowSize,
		},
	)
	if err != nil {
		return false, errors.Wrap(errors.CodeCryptoError, err, "failed to validate TOTP code")
	}

	return valid, nil
}

// GenerateCode generates a current TOTP code for a secret
func (p *TOTPProvider) GenerateCode(secret string) (string, error) {
	// Normalize the secret
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))

	// Generate the code
	code, err := totp.GenerateCodeCustom(
		secret,
		time.Now(),
		totp.ValidateOpts{
			Digits:    p.config.Digits,
			Algorithm: p.config.Algorithm,
			Period:    p.config.Period,
		},
	)
	if err != nil {
		return "", errors.Wrap(errors.CodeCryptoError, err, "failed to generate TOTP code")
	}

	return code, nil
}

// FormatSecret formats a raw secret to be more user-friendly
func (p *TOTPProvider) FormatSecret(secret string) string {
	// Convert to uppercase and insert a space every 4 characters
	secret = strings.ToUpper(secret)
	formattedSecret := ""
	for i, char := range secret {
		if i > 0 && i%4 == 0 {
			formattedSecret += " "
		}
		formattedSecret += string(char)
	}
	return formattedSecret
}

// ParseSecret parses a formatted secret back to its raw form
func (p *TOTPProvider) ParseSecret(formattedSecret string) string {
	// Remove spaces and convert to uppercase
	return strings.ToUpper(strings.ReplaceAll(formattedSecret, " ", ""))
}

// GetOTPAuthURL generates an otpauth URL for a given user and secret
func (p *TOTPProvider) GetOTPAuthURL(userIdentifier, secret string) string {
	// Normalize the secret
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))

	// Create the URL
	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   fmt.Sprintf("/%s:%s", url.PathEscape(p.config.Issuer), url.PathEscape(userIdentifier)),
	}

	params := url.Values{}
	params.Add("secret", secret)
	params.Add("issuer", p.config.Issuer)
	params.Add("algorithm", getAlgorithmString(p.config.Algorithm))
	params.Add("digits", getDigitsString(p.config.Digits))
	params.Add("period", fmt.Sprintf("%d", p.config.Period))

	u.RawQuery = params.Encode()
	return u.String()
}

// TOTPSecret contains data for a generated TOTP secret
type TOTPSecret struct {
	Secret    string // The base32 encoded secret
	URL       string // The otpauth URL
	QRCodePNG []byte // QR code image data in PNG format
}

// Helper functions to convert otp types to strings
func getAlgorithmString(algorithm otp.Algorithm) string {
	switch algorithm {
	case otp.AlgorithmSHA1:
		return "SHA1"
	case otp.AlgorithmSHA256:
		return "SHA256"
	case otp.AlgorithmSHA512:
		return "SHA512"
	default:
		return "SHA1"
	}
}

func getDigitsString(digits otp.Digits) string {
	switch digits {
	case otp.DigitsSix:
		return "6"
	case otp.DigitsEight:
		return "8"
	default:
		return "6"
	}
}

// ConvertImageToBytes encodes an image.Image into a PNG byte slice.
func ConvertImageToBytes(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	err := png.Encode(&buf, img)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

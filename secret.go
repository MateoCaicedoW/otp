package otp

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// GenerateSecret generates a new random secret key
func GenerateSecret(length int) (string, error) {
	if length <= 0 {
		length = 32 // Default length
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return base32.StdEncoding.EncodeToString(bytes), nil
}

// ValidateSecret checks if the provided secret is valid base32
func ValidateSecret(secret string) error {
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	_, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return fmt.Errorf("invalid base32 secret: %w", err)
	}
	return nil
}

// decodeSecret decodes the base32 secret
func (c *Config) decodeSecret() ([]byte, error) {
	secret := strings.ToUpper(strings.ReplaceAll(c.Secret, " ", ""))
	return base32.StdEncoding.DecodeString(secret)
}

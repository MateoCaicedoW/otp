// Package otp provides functionality for generating and validating
// Time-based One-Time Passwords (TOTP) and HMAC-based One-Time Passwords (HOTP).
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

// Algorithm represents the hashing algorithm used for OTP generation
type Algorithm int

const (
	AlgorithmSHA1 Algorithm = iota
	AlgorithmSHA256
	AlgorithmSHA512
)

// String returns the string representation of the algorithm
func (a Algorithm) String() string {
	switch a {
	case AlgorithmSHA1:
		return "SHA1"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	default:
		return "SHA1"
	}
}

// Config holds the configuration for OTP generation
type Config struct {
	// Secret is the shared secret key (base32 encoded)
	Secret string
	// Digits is the number of digits in the OTP (default: 6)
	Digits int
	// Algorithm is the hashing algorithm (default: SHA1)
	Algorithm Algorithm
	// Period is the time period in seconds for TOTP (default: 30)
	Period int
	// Counter is the counter value for HOTP
	Counter uint64
	// Issuer is the name of the service issuing the OTP
	Issuer string
	// AccountName is the name of the account
	AccountName string
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Digits:    6,
		Algorithm: AlgorithmSHA1,
		Period:    30,
		Counter:   0,
	}
}

// IncrementCounter increments the HOTP counter and returns the new value
func (c *Config) IncrementCounter() uint64 {
	c.Counter++
	return c.Counter
}

// SetCounter sets the HOTP counter to a specific value
func (c *Config) SetCounter(counter uint64) {
	c.Counter = counter
}

// getHash returns the appropriate hash function based on the algorithm
func (c *Config) getHash() func() hash.Hash {
	switch c.Algorithm {
	case AlgorithmSHA256:
		return sha256.New
	case AlgorithmSHA512:
		return sha512.New
	default:
		return sha1.New
	}
}

// generateOTP generates an OTP for the given counter value
func (c *Config) generateOTP(counter uint64) (string, error) {
	if c.Digits <= 0 || c.Digits > 10 {
		return "", ErrInvalidDigits
	}

	secretBytes, err := c.decodeSecret()
	if err != nil {
		return "", fmt.Errorf("failed to decode secret: %w", err)
	}

	// Convert counter to byte array
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	// Generate HMAC
	h := hmac.New(c.getHash(), secretBytes)
	h.Write(counterBytes)
	hash := h.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0x0f
	truncatedHash := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	// Generate OTP
	otp := truncatedHash % uint32(math.Pow10(c.Digits))

	// Format with leading zeros
	format := fmt.Sprintf("%%0%dd", c.Digits)
	return fmt.Sprintf(format, otp), nil
}

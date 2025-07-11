package otp

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// GenerateBackupCodes generates a set of backup codes for recovery purposes
func GenerateBackupCodes(count int) ([]string, error) {
	if count <= 0 {
		count = 10 // Default backup codes count
	}

	codes := make([]string, count)
	for i := 0; i < count; i++ {
		bytes := make([]byte, 5) // 5 bytes = 8 characters in base32
		if _, err := rand.Read(bytes); err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}

		// Convert to base32 and format as XXXX-XXXX
		code := base32.StdEncoding.EncodeToString(bytes)
		code = strings.TrimRight(code, "=") // Remove padding
		if len(code) >= 8 {
			codes[i] = fmt.Sprintf("%s-%s", code[:4], code[4:8])
		} else {
			codes[i] = code
		}
	}

	return codes, nil
}

// ValidateBackupCode validates a backup code (simple constant-time comparison)
func ValidateBackupCode(providedCode, storedCode string) bool {
	// Normalize codes (remove spaces, convert to uppercase)
	provided := strings.ToUpper(strings.ReplaceAll(providedCode, " ", ""))
	provided = strings.ReplaceAll(provided, "-", "")

	stored := strings.ToUpper(strings.ReplaceAll(storedCode, " ", ""))
	stored = strings.ReplaceAll(stored, "-", "")

	// Constant-time comparison to prevent timing attacks
	if len(provided) != len(stored) {
		return false
	}

	var result byte
	for i := 0; i < len(provided); i++ {
		result |= provided[i] ^ stored[i]
	}

	return result == 0
}

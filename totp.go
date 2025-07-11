package otp

import (
	"fmt"
	"time"
)

// NewTOTP creates a new TOTP configuration
func NewTOTP(secret, issuer, accountName string, digits, period int) *Config {
	return &Config{
		Secret:      secret,
		Digits:      digits,
		Algorithm:   AlgorithmSHA1,
		Period:      period,
		Issuer:      issuer,
		AccountName: accountName,
	}
}

// TOTPEntry represents a TOTP code with its validity period
type TOTPEntry struct {
	Code      string
	ValidFrom time.Time
	ValidTo   time.Time
	IsCurrent bool
}

// IsValid checks if the TOTP entry is valid at the given time
func (e *TOTPEntry) IsValid(t time.Time) bool {
	return !t.Before(e.ValidFrom) && t.Before(e.ValidTo)
}

// String returns a string representation of the TOTP entry
func (e *TOTPEntry) String() string {
	status := "future"
	if e.IsCurrent {
		status = "current"
	} else if time.Now().After(e.ValidTo) {
		status = "expired"
	}

	return fmt.Sprintf("Code: %s, Valid: %s to %s (%s)",
		e.Code,
		e.ValidFrom.Format("15:04:05"),
		e.ValidTo.Format("15:04:05"),
		status)
}

// GenerateTOTP generates a Time-based OTP for the current time
func (c *Config) GenerateTOTP() (string, error) {
	return c.GenerateTOTPAt(time.Now())
}

// GenerateTOTPAt generates a Time-based OTP for the specified time
func (c *Config) GenerateTOTPAt(t time.Time) (string, error) {
	if c.Period <= 0 {
		c.Period = 30
	}

	counter := uint64(t.Unix()) / uint64(c.Period)
	return c.generateOTP(counter)
}

// ValidateTOTP validates a TOTP code with a time window
func (c *Config) ValidateTOTP(code string, windowSize int) (bool, error) {
	return c.ValidateTOTPAt(code, time.Now(), windowSize)
}

// ValidateTOTPAt validates a TOTP code at a specific time with a time window
func (c *Config) ValidateTOTPAt(code string, t time.Time, windowSize int) (bool, error) {
	if windowSize < 0 {
		windowSize = 1 // Default window size
	}

	currentCounter := uint64(t.Unix()) / uint64(c.Period)

	// Check current time and surrounding windows
	for i := -windowSize; i <= windowSize; i++ {
		counter := currentCounter + uint64(i)
		expectedCode, err := c.generateOTP(counter)
		if err != nil {
			return false, err
		}

		if code == expectedCode {
			return true, nil
		}
	}

	return false, nil
}

// GetRemainingTime returns the remaining time in seconds until the current TOTP expires
func (c *Config) GetRemainingTime() int {
	if c.Period <= 0 {
		c.Period = 30
	}

	now := time.Now().Unix()
	return c.Period - int(now%int64(c.Period))
}

// GetNextTOTPTime returns the time when the next TOTP will be generated
func (c *Config) GetNextTOTPTime() time.Time {
	if c.Period <= 0 {
		c.Period = 30
	}

	now := time.Now()
	currentPeriod := now.Unix() / int64(c.Period)
	nextPeriod := currentPeriod + 1

	return time.Unix(nextPeriod*int64(c.Period), 0)
}

// GetCurrentTOTPWindow returns the current time window for TOTP
func (c *Config) GetCurrentTOTPWindow() (start, end time.Time) {
	if c.Period <= 0 {
		c.Period = 30
	}

	now := time.Now()
	currentPeriod := now.Unix() / int64(c.Period)

	start = time.Unix(currentPeriod*int64(c.Period), 0)
	end = time.Unix((currentPeriod+1)*int64(c.Period), 0)

	return start, end
}

// GenerateTOTPBatch generates multiple TOTPs for different time windows
func (c *Config) GenerateTOTPBatch(windowCount int) ([]TOTPEntry, error) {
	if windowCount <= 0 {
		windowCount = 3
	}

	entries := make([]TOTPEntry, windowCount)
	baseTime := time.Now()

	for i := 0; i < windowCount; i++ {
		offset := i - (windowCount / 2) // Center around current time
		targetTime := baseTime.Add(time.Duration(offset*c.Period) * time.Second)

		code, err := c.GenerateTOTPAt(targetTime)
		if err != nil {
			return nil, fmt.Errorf("failed to generate TOTP for window %d: %w", i, err)
		}

		start, end := c.GetCurrentTOTPWindow()
		if offset != 0 {
			start = start.Add(time.Duration(offset*c.Period) * time.Second)
			end = end.Add(time.Duration(offset*c.Period) * time.Second)
		}

		entries[i] = TOTPEntry{
			Code:      code,
			ValidFrom: start,
			ValidTo:   end,
			IsCurrent: offset == 0,
		}
	}

	return entries, nil
}

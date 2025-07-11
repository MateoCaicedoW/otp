package otp

// NewHOTP creates a new HOTP configuration
func NewHOTP(secret, issuer, accountName string, digits int, counter uint64) *Config {
	return &Config{
		Secret:      secret,
		Digits:      digits,
		Algorithm:   AlgorithmSHA1,
		Counter:     counter,
		Issuer:      issuer,
		AccountName: accountName,
	}
}

// GenerateHOTP generates a Counter-based OTP
func (c *Config) GenerateHOTP() (string, error) {
	return c.generateOTP(c.Counter)
}

// GenerateHOTPAt generates a Counter-based OTP for the specified counter
func (c *Config) GenerateHOTPAt(counter uint64) (string, error) {
	return c.generateOTP(counter)
}

// ValidateHOTP validates a HOTP code for a range of counter values
func (c *Config) ValidateHOTP(code string, windowSize int) (bool, uint64, error) {
	if windowSize < 0 {
		windowSize = 10 // Default window size
	}

	for i := 0; i <= windowSize; i++ {
		counter := c.Counter + uint64(i)
		expectedCode, err := c.generateOTP(counter)
		if err != nil {
			return false, 0, err
		}

		if code == expectedCode {
			return true, counter, nil
		}
	}

	return false, 0, nil
}

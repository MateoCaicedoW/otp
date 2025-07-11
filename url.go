package otp

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// QRCodeURL generates a QR code URL for authenticator apps using qr-server.com
func (c *Config) QRCodeURL() (string, error) {
	if c.Secret == "" {
		return "", ErrMissingSecret
	}

	if c.AccountName == "" {
		return "", ErrMissingAccountName
	}

	//  the otpauth URL first
	otpauthURL, err := c.OTPAuthURL()
	if err != nil {
		return "", err
	}

	// Generate QR code URL using qr-server.com (free service)
	qrURL := fmt.Sprintf("https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=%s",
		url.QueryEscape(otpauthURL))

	return qrURL, nil
}

// QRCodeURLWithCustomSize generates a QR code URL with custom size
func (c *Config) QRCodeURLWithCustomSize(size int) (string, error) {
	if size <= 0 {
		size = 200 // Default size
	}

	if c.Secret == "" {
		return "", ErrMissingSecret
	}

	if c.AccountName == "" {
		return "", ErrMissingAccountName
	}

	//  the otpauth URL first
	otpauthURL, err := c.OTPAuthURL()
	if err != nil {
		return "", err
	}

	// Generate QR code URL with custom size
	qrURL := fmt.Sprintf("https://api.qrserver.com/v1/create-qr-code/?size=%dx%d&data=%s",
		size, size, url.QueryEscape(otpauthURL))

	return qrURL, nil
}

// OTPAuthURL returns the otpauth:// URL for authenticator apps
func (c *Config) OTPAuthURL() (string, error) {
	if c.Secret == "" {
		return "", ErrMissingSecret
	}

	if c.AccountName == "" {
		return "", ErrMissingAccountName
	}

	params := url.Values{}
	params.Set("secret", c.Secret)
	params.Set("digits", strconv.Itoa(c.Digits))
	params.Set("algorithm", c.Algorithm.String())

	var otpType, label string
	if c.Period > 0 {
		// TOTP
		otpType = "totp"
		params.Set("period", strconv.Itoa(c.Period))
	} else {
		// HOTP
		otpType = "hotp"
		params.Set("counter", strconv.FormatUint(c.Counter, 10))
	}

	if c.Issuer != "" {
		label = fmt.Sprintf("%s:%s", c.Issuer, c.AccountName)
		params.Set("issuer", c.Issuer)
	} else {
		label = c.AccountName
	}

	return fmt.Sprintf("otpauth://%s/%s?%s", otpType, url.QueryEscape(label), params.Encode()), nil
}

// ParseOTPAuthURL parses an otpauth:// URL and returns a Config
func ParseOTPAuthURL(otpauthURL string) (*Config, error) {
	u, err := url.Parse(otpauthURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if u.Scheme != "otpauth" {
		return nil, fmt.Errorf("invalid scheme: expected otpauth, got %s", u.Scheme)
	}

	config := DefaultConfig()

	// Parse OTP type
	switch u.Host {
	case "totp":
		config.Period = 30 // Default for TOTP
	case "hotp":
		config.Period = 0 // Indicates HOTP
	default:
		return nil, fmt.Errorf("unsupported OTP type: %s", u.Host)
	}

	// Parse label (issuer:account or just account)
	label := strings.TrimPrefix(u.Path, "/")
	if label == "" {
		return nil, ErrMissingAccountName
	}

	parts := strings.SplitN(label, ":", 2)
	if len(parts) == 2 {
		config.Issuer = parts[0]
		config.AccountName = parts[1]
	} else {
		config.AccountName = parts[0]
	}

	// Parse query parameters
	params := u.Query()

	// Secret (required)
	secret := params.Get("secret")
	if secret == "" {
		return nil, ErrMissingSecret
	}
	config.Secret = secret

	// Digits
	if digits := params.Get("digits"); digits != "" {
		if d, err := strconv.Atoi(digits); err == nil && d > 0 && d <= 10 {
			config.Digits = d
		}
	}

	// Algorithm
	if algorithm := params.Get("algorithm"); algorithm != "" {
		switch strings.ToUpper(algorithm) {
		case "SHA1":
			config.Algorithm = AlgorithmSHA1
		case "SHA256":
			config.Algorithm = AlgorithmSHA256
		case "SHA512":
			config.Algorithm = AlgorithmSHA512
		}
	}

	// Period (for TOTP)
	if config.Period > 0 {
		if period := params.Get("period"); period != "" {
			if p, err := strconv.Atoi(period); err == nil && p > 0 {
				config.Period = p
			}
		}
	}

	// Counter (for HOTP)
	if config.Period == 0 {
		if counter := params.Get("counter"); counter != "" {
			if c, err := strconv.ParseUint(counter, 10, 64); err == nil {
				config.Counter = c
			}
		}
	}

	// Issuer (can override the one from label)
	if issuer := params.Get("issuer"); issuer != "" {
		config.Issuer = issuer
	}

	return config, nil
}

// QRCodeURLQuickChart generates a QR code URL using QuickChart.io
func (c *Config) QRCodeURLQuickChart() (string, error) {
	if c.Secret == "" {
		return "", ErrMissingSecret
	}

	if c.AccountName == "" {
		return "", ErrMissingAccountName
	}

	//  the otpauth URL first
	otpauthURL, err := c.OTPAuthURL()
	if err != nil {
		return "", err
	}

	// Generate QR code URL using QuickChart.io
	qrURL := fmt.Sprintf("https://quickchart.io/qr?text=%s&size=200",
		url.QueryEscape(otpauthURL))

	return qrURL, nil
}

// QRCodeURLGoQR generates a QR code URL using goQR.me
func (c *Config) QRCodeURLGoQR() (string, error) {
	if c.Secret == "" {
		return "", ErrMissingSecret
	}

	if c.AccountName == "" {
		return "", ErrMissingAccountName
	}

	//  the otpauth URL first
	otpauthURL, err := c.OTPAuthURL()
	if err != nil {
		return "", err
	}

	// Generate QR code URL using goQR.me
	qrURL := fmt.Sprintf("https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=%s",
		url.QueryEscape(otpauthURL))

	return qrURL, nil
}

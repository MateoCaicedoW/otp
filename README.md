# OTP Package

A comprehensive Go package for generating and validating Time-based One-Time Passwords (TOTP) and HMAC-based One-Time Passwords (HOTP). This package provides a complete implementation following RFC 4226 (HOTP) and RFC 6238 (TOTP) standards.

## Features

- **TOTP (Time-based OTP)** generation and validation
- **HOTP (Counter-based OTP)** generation and validation
- Support for multiple hashing algorithms (SHA1, SHA256, SHA512)
- Configurable OTP length (1-10 digits)
- QR code URL generation for authenticator apps
- Backup code generation and validation
- OTPAuth URL parsing and generation
- Time window validation with configurable tolerance
- Batch TOTP generation for multiple time windows

## Installation

```bash
go get github.com/MateoCaicedoW/otp
```

## Quick Start

### Basic TOTP Usage

```go
package main

import (
    "fmt"
    "log"
    "github.com/MateoCaicedoW/otp"
)

func main() {
    // Generate a new secret
    secret, err := otp.GenerateSecret(32)
    if err != nil {
        log.Fatal(err)
    }

    // Create TOTP configuration
    config := otp.NewTOTP(secret, "MyApp", "user@example.com", 6, 30)

    // Generate current TOTP
    code, err := config.GenerateTOTP()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Current TOTP: %s\n", code)
    
    // Validate TOTP
    valid, err := config.ValidateTOTP(code, 1)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Valid: %v\n", valid)
}
```

### Basic HOTP Usage

```go
// Create HOTP configuration
config := otp.NewHOTP(secret, "MyApp", "user@example.com", 6, 0)

// Generate HOTP
code, err := config.GenerateHOTP()
if err != nil {
    log.Fatal(err)
}

// Validate HOTP
valid, newCounter, err := config.ValidateHOTP(code, 10)
if err != nil {
    log.Fatal(err)
}

if valid {
    // Update counter for next use
    config.SetCounter(newCounter + 1)
}
```

## Configuration

### Config Structure

```go
type Config struct {
    Secret      string    // Base32 encoded secret key
    Digits      int       // Number of digits (1-10, default: 6)
    Algorithm   Algorithm // Hash algorithm (SHA1, SHA256, SHA512)
    Period      int       // Time period in seconds for TOTP (default: 30)
    Counter     uint64    // Counter value for HOTP
    Issuer      string    // Service name
    AccountName string    // Account identifier
}
```

### Supported Algorithms

- `AlgorithmSHA1` - SHA1 (default, most compatible)
- `AlgorithmSHA256` - SHA256 (more secure)
- `AlgorithmSHA512` - SHA512 (most secure)

### Creating Configurations

```go
// Default configuration
config := otp.DefaultConfig()

// Custom TOTP
config := otp.NewTOTP("JBSWY3DPEHPK3PXP", "MyApp", "user@example.com", 6, 30)

// Custom HOTP
config := otp.NewHOTP("JBSWY3DPEHPK3PXP", "MyApp", "user@example.com", 6, 0)

// Manual configuration
config := &otp.Config{
    Secret:      "JBSWY3DPEHPK3PXP",
    Digits:      8,
    Algorithm:   otp.AlgorithmSHA256,
    Period:      60,
    Issuer:      "MyApp",
    AccountName: "user@example.com",
}
```

## API Reference

### Secret Management

```go
// Generate a new random secret
secret, err := otp.GenerateSecret(32)

// Validate existing secret
err := otp.ValidateSecret("JBSWY3DPEHPK3PXP")
```

### TOTP Functions

```go
// Generate TOTP for current time
code, err := config.GenerateTOTP()

// Generate TOTP for specific time
code, err := config.GenerateTOTPAt(time.Now())

// Validate TOTP with time window
valid, err := config.ValidateTOTP(code, 1) // 1 = ±30 seconds

// Validate TOTP at specific time
valid, err := config.ValidateTOTPAt(code, time.Now(), 1)

// Get remaining time for current TOTP
remaining := config.GetRemainingTime()

// Get next TOTP generation time
nextTime := config.GetNextTOTPTime()

// Get current time window
start, end := config.GetCurrentTOTPWindow()

// Generate multiple TOTPs for different windows
entries, err := config.GenerateTOTPBatch(5)
```

### HOTP Functions

```go
// Generate HOTP with current counter
code, err := config.GenerateHOTP()

// Generate HOTP with specific counter
code, err := config.GenerateHOTPAt(counter)

// Validate HOTP
valid, newCounter, err := config.ValidateHOTP(code, 10)

// Increment counter
newCounter := config.IncrementCounter()

// Set specific counter
config.SetCounter(42)
```

### QR Code and URLs

```go
// Generate QR code URL for Google Charts
qrURL, err := config.GetQRCodeURL()

// Generate OTPAuth URL
otpauthURL, err := config.GetOTPAuthURL()

// Parse OTPAuth URL
config, err := otp.ParseOTPAuthURL("otpauth://totp/MyApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp")
```

### Backup Codes

```go
// Generate backup codes
codes, err := otp.GenerateBackupCodes(10)

// Validate backup code
valid := otp.ValidateBackupCode("ABCD-EFGH", storedCode)
```

## Examples

### Integrating with Authenticator Apps

```go
// Create configuration
config := otp.NewTOTP(secret, "MyApp", "user@example.com", 6, 30)

// Generate QR code URL for setup
qrURL, err := config.GetQRCodeURL()
if err != nil {
    log.Fatal(err)
}

// Display QR code to user
fmt.Printf("Scan this QR code: %s\n", qrURL)

// Or provide the OTPAuth URL directly
otpauthURL, err := config.GetOTPAuthURL()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Manual entry URL: %s\n", otpauthURL)
```

### Two-Factor Authentication Flow

```go
// During login, after username/password verification
userCode := getUserInput() // Get code from user

// Validate with small time window tolerance
valid, err := config.ValidateTOTP(userCode, 1)
if err != nil {
    log.Fatal(err)
}

if valid {
    // Grant access
    fmt.Println("Access granted!")
} else {
    // Reject access
    fmt.Println("Invalid code")
}
```


### Working with Different Algorithms

```go
// SHA256 TOTP
config := &otp.Config{
    Secret:      secret,
    Digits:      8,
    Algorithm:   otp.AlgorithmSHA256,
    Period:      60,
    Issuer:      "SecureApp",
    AccountName: "user@example.com",
}

code, err := config.GenerateTOTP()
```

## Security Considerations

1. **Secret Storage**: Store secrets securely, preferably encrypted
2. **Time Synchronization**: Ensure server time is synchronized (NTP)
3. **Window Size**: Use minimal validation windows to reduce attack surface
4. **Rate Limiting**: Implement rate limiting for validation attempts
5. **Backup Codes**: Generate and securely store backup codes
6. **Algorithm Choice**: Consider SHA256 or SHA512 for new implementations

## Testing

```go
// Test with specific time
testTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
code, err := config.GenerateTOTPAt(testTime)

// Test validation
valid, err := config.ValidateTOTPAt(code, testTime, 0)
```

## Compatibility

This package is compatible with popular authenticator applications including:
- Google Authenticator
- Authy
- Microsoft Authenticator
- 1Password
- Bitwarden
- Any RFC 6238/4226 compliant app

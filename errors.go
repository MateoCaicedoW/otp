package otp

import "errors"

var (
	ErrInvalidDigits      = errors.New("digits must be between 1 and 10")
	ErrInvalidSecret      = errors.New("invalid base32 secret")
	ErrMissingSecret      = errors.New("secret is required")
	ErrMissingAccountName = errors.New("account name is required")
	ErrInvalidAlgorithm   = errors.New("invalid algorithm")
	ErrInvalidPeriod      = errors.New("period must be greater than 0")
	ErrInvalidCounter     = errors.New("counter must be non-negative")
)

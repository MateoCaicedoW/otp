package main

import (
	"log/slog"

	"github.com/MateoCaicedoW/otp"
)

func main() {

	secret, err := otp.GenerateSecret(32)
	if err != nil {
		slog.Error("Failed to generate secret", "error", err)
		return
	}

	// ==== Create a new TOTP configuration
	// The secret should be a base32 encoded string
	otpConfig := otp.NewTOTP(
		secret,
		"Myapp",
		"Mateo Caicedo",
		6,
		300,
	)

	// Generate a TOTP code
	code, err := otpConfig.GenerateTOTP()
	if err != nil {
		slog.Error("Failed to generate TOTP code", "error", err)
		return
	}

	slog.Info("Generated TOTP code", "code", code)

	qrCodeURL, err := otpConfig.QRCodeURLWithCustomSize(400)
	if err != nil {
		slog.Error("Failed to generate QR code URL", "error", err)
		return
	}

	slog.Info("QR Code URL", "url", qrCodeURL)

	// Validate the TOTP code
	valid, err := otpConfig.ValidateTOTP(code, 1)
	if err != nil {
		slog.Error("Failed to validate TOTP code", "error", err)
		return
	}

	if valid {
		slog.Info("TOTP code is valid")
	} else {
		slog.Warn("TOTP code is invalid")
	}
}

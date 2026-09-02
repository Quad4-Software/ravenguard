// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package access

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 1
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16

	// MinPINLen is the minimum length for PIN secrets.
	MinPINLen = 4
	// MinPasswordLen is the minimum length for password secrets.
	MinPasswordLen = 8
	// MaxSecretLen is the maximum length for any access secret.
	MaxSecretLen = 128
)

var (
	ErrInvalidHash    = errors.New("invalid argon2id hash")
	ErrSecretMismatch = errors.New("secret mismatch")
	ErrSecretTooShort = errors.New("secret too short")
	ErrSecretTooLong  = errors.New("secret too long")
)

// ValidateSecret checks secret length against minLen and MaxSecretLen.
func ValidateSecret(secret string, minLen int) error {
	if minLen < 1 {
		minLen = MinPINLen
	}
	if len(secret) < minLen {
		return ErrSecretTooShort
	}
	if len(secret) > MaxSecretLen {
		return ErrSecretTooLong
	}
	return nil
}

// HashSecret returns an encoded argon2id hash of secret.
// minLen is the minimum accepted plaintext length (use MinPINLen or MinPasswordLen).
func HashSecret(secret string, minLen int) (string, error) {
	if err := ValidateSecret(secret, minLen); err != nil {
		return "", err
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(secret), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64Salt, b64Hash), nil
}

// VerifySecret checks secret against an encoded argon2id hash.
func VerifySecret(encoded, secret string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return ErrInvalidHash
	}
	var memory, timeCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return ErrInvalidHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return ErrInvalidHash
	}
	if len(want) == 0 || len(want) > 64 {
		return ErrInvalidHash
	}
	got := argon2.IDKey([]byte(secret), salt, timeCost, memory, threads, uint32(len(want))) //nolint:gosec // G115: key length bounded above
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrSecretMismatch
	}
	return nil
}

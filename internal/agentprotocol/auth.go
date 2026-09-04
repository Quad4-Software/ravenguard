// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package agentprotocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const hubKeyFile = "hub_ed25519.key"
const hubPubFile = "hub_ed25519.pub"

// KeyPair is the hub Ed25519 identity used to prove hub authenticity to agents.
type KeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Private: priv, Public: pub}, nil
}

func (k KeyPair) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(k.Public)
}

func ParsePublicKeyBase64(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty public key")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size")
	}
	return ed25519.PublicKey(raw), nil
}

func LoadOrCreateKeyPair(dataDir string) (KeyPair, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return KeyPair{}, err
	}
	keyPath := filepath.Join(dataDir, hubKeyFile)
	pubPath := filepath.Join(dataDir, hubPubFile)
	raw, err := os.ReadFile(keyPath)
	if err == nil {
		priv, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if decErr != nil {
			return KeyPair{}, fmt.Errorf("hub key: %w", decErr)
		}
		if len(priv) != ed25519.PrivateKeySize {
			return KeyPair{}, fmt.Errorf("hub key: invalid size")
		}
		kp := KeyPair{Private: ed25519.PrivateKey(priv), Public: ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)}
		_ = os.WriteFile(pubPath, []byte(kp.PublicKeyBase64()+"\n"), 0o600)
		return kp, nil
	}
	if !os.IsNotExist(err) {
		return KeyPair{}, err
	}
	kp, err := GenerateKeyPair()
	if err != nil {
		return KeyPair{}, err
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(kp.Private)+"\n"), 0o600); err != nil {
		return KeyPair{}, err
	}
	if err := os.WriteFile(pubPath, []byte(kp.PublicKeyBase64()+"\n"), 0o600); err != nil {
		return KeyPair{}, err
	}
	return kp, nil
}

func challengeMessage(tokenHash, nonce string, ts int64) []byte {
	return []byte(tokenHash + "|" + nonce + "|" + strconv.FormatInt(ts, 10))
}

func SignChallenge(priv ed25519.PrivateKey, tokenHash, nonce string, ts int64) string {
	sig := ed25519.Sign(priv, challengeMessage(tokenHash, nonce, ts))
	return base64.StdEncoding.EncodeToString(sig)
}

func VerifyChallenge(pub ed25519.PublicKey, tokenHash, nonce string, ts int64, sigB64 string) error {
	now := time.Now().Unix()
	if ts < now-ChallengeSkew || ts > now+ChallengeSkew {
		return fmt.Errorf("challenge timestamp out of window")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("bad signature encoding")
	}
	if !ed25519.Verify(pub, challengeMessage(tokenHash, nonce, ts), sig) {
		return fmt.Errorf("invalid hub signature")
	}
	return nil
}

func RandomNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TokenEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// MachineFingerprint returns a stable-ish host identity hash.
func MachineFingerprint() (string, error) {
	host, _ := os.Hostname()
	machineID := ""
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		machineID = strings.TrimSpace(string(b))
	}
	if machineID == "" {
		if b, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
			machineID = strings.TrimSpace(string(b))
		}
	}
	seed := host + "|" + machineID
	if seed == "|" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		seed = hex.EncodeToString(b)
	}
	sum := sha256.Sum256([]byte("ravenguard-agent|" + seed))
	return hex.EncodeToString(sum[:]), nil
}

func NewToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "rgpt_" + hex.EncodeToString(b), nil
}

func NewID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

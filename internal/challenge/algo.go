// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
)

// VerifySolution checks that sol satisfies the challenge PoW.
func VerifySolution(ch Challenge, sol uint64) error {
	switch ch.Algorithm {
	case AlgoSHA256, "":
		if !checkPoW(ch.Challenge, sol, ch.Difficulty) {
			return ErrBadSolution
		}
		return nil
	case AlgoPBKDF2SHA256:
		iters := 10000
		if ch.Params != nil {
			if v, ok := ch.Params["iterations"]; ok && v > 0 {
				iters = v
			}
		}
		if !checkPBKDF2(ch.Challenge, ch.Salt, sol, ch.Difficulty, iters) {
			return ErrBadSolution
		}
		return nil
	case AlgoArgon2id:
		// Argon2id lands with the widget worker; reject until wired.
		return ErrBadAlgorithm
	default:
		return ErrBadAlgorithm
	}
}

func checkPBKDF2(challenge, saltHex string, sol uint64, difficulty, iterations int) bool {
	salt, err := hex.DecodeString(saltHex)
	if err != nil || len(salt) == 0 {
		return false
	}
	password := challenge + ":" + strconv.FormatUint(sol, 10)
	dk, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return false
	}
	return leadingZeroBits(dk) >= difficulty
}

// SolveChallenge finds a solution for tests and fixture generation.
func SolveChallenge(ch Challenge) (uint64, error) {
	limit := ch.MaxNumber
	if limit == 0 {
		limit = maxNumberFor(ch.Difficulty)
	}
	for i := uint64(0); i <= limit; i++ {
		if err := VerifySolution(ch, i); err == nil {
			return i, nil
		}
	}
	return 0, ErrBadSolution
}

// HashSolutionSHA256 returns the digest used for SHA-256 PoW (for fixtures).
func HashSolutionSHA256(nonce string, solution uint64) []byte {
	h := sha256.New()
	_, _ = h.Write(stringBytes(nonce))
	_, _ = h.Write(colonSep)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], solution)
	_, _ = h.Write(b[:])
	sum := h.Sum(nil)
	return sum
}

// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package sandbox

import "strings"

// FromFileConfig builds a runtime Config from TOML-backed fields.
func FromFileConfig(
	mode string,
	llMode string,
	scMode string,
	roDirs, rwDirs, roFiles, rwFiles []string,
	restrictNet, restrictScoped, ignoreMissing bool,
	bindTCP, bindUDP, connectTCP, connectUDP []uint16,
	denyAction string,
) (Config, error) {
	m, err := ParseMode(mode)
	if err != nil {
		return Config{}, err
	}
	lm, err := ParseMode(llMode)
	if err != nil {
		return Config{}, err
	}
	sm, err := ParseMode(scMode)
	if err != nil {
		return Config{}, err
	}
	return Config{
		Mode: m,
		Landlock: LandlockConfig{
			Mode:           lm,
			RODirs:         append([]string(nil), roDirs...),
			RWDirs:         append([]string(nil), rwDirs...),
			ROFiles:        append([]string(nil), roFiles...),
			RWFiles:        append([]string(nil), rwFiles...),
			RestrictNet:    restrictNet,
			RestrictScoped: restrictScoped,
			BindTCP:        append([]uint16(nil), bindTCP...),
			BindUDP:        append([]uint16(nil), bindUDP...),
			ConnectTCP:     append([]uint16(nil), connectTCP...),
			ConnectUDP:     append([]uint16(nil), connectUDP...),
			IgnoreMissing:  ignoreMissing,
		},
		Seccomp: SeccompConfig{
			Mode:       sm,
			DenyAction: strings.TrimSpace(denyAction),
		},
	}, nil
}

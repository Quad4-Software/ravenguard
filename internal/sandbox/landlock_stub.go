// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//go:build !linux

package sandbox

func applyLandlock(_ LandlockConfig, _ Mode) (string, error) {
	return "", errUnsupported("landlock")
}

func AvailableLandlock() string {
	return "unsupported"
}

// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package sandbox

// Config is the runtime sandbox policy assembled from TOML and derived paths.
type Config struct {
	Mode     Mode
	Landlock LandlockConfig
	Seccomp  SeccompConfig
}

// LandlockConfig configures Linux Landlock LSM restrictions.
type LandlockConfig struct {
	Mode           Mode
	RODirs         []string
	RWDirs         []string
	ROFiles        []string
	RWFiles        []string
	RestrictNet    bool
	RestrictScoped bool
	BindTCP        []uint16
	BindUDP        []uint16
	ConnectTCP     []uint16
	ConnectUDP     []uint16
	IgnoreMissing  bool
}

// SeccompConfig configures in-process seccomp-bpf filtering.
type SeccompConfig struct {
	Mode       Mode
	DenyAction string
}

func (c Config) landlockMode() Mode {
	if c.Landlock.Mode != "" {
		return c.Landlock.Mode
	}
	return c.Mode
}

func (c Config) seccompMode() Mode {
	if c.Seccomp.Mode != "" {
		return c.Seccomp.Mode
	}
	return c.Mode
}

// SeccompEnabled reports whether seccomp filtering should be applied.
func (c Config) SeccompEnabled() bool {
	return c.seccompMode().Enabled()
}

// NeedsClassicTCP reports whether listeners must avoid Multipath TCP so
// Landlock network rules can apply to net.Listen (classic TCP only).
func (c Config) NeedsClassicTCP() bool {
	m := c.landlockMode()
	return m.Enabled() && c.Landlock.RestrictNet
}

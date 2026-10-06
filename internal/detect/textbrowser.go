// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package detect

import "github.com/Quad4-Software/ravenguard/internal/faststr"

// textBrowserUAs matches browsers with no JavaScript engine or engines too
// old to run the proof-of-work widget. These are real user agents on minimal,
// legacy, assistive, and text-mode setups.
var textBrowserUAs = []string{
	"lynx/", "links (", "elinks", "w3m/", "emacs-w3", "dillo/",
	"netsurf", "browsh/", "edbrowse", "retawq", "mothra", "amaya/",
	"charlotte/", "serenityos", "netcompletes", "wwwoffle",
}

var textBrowserMatcher = faststr.NewMatcher(textBrowserUAs)

// IsTextBrowserUA reports whether ua names a no-JS or text-mode browser.
func IsTextBrowserUA(ua string) bool {
	return ua != "" && matchAnyFold(ua, textBrowserMatcher)
}

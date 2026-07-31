//go:build !linux

package appstate

// DNSCaptureIsComplete is true on every platform but Linux — see
// dnscapture_linux.go for what Linux cannot capture and why.
//
// Windows needs none: a Windows resolver's configured servers are ordinary
// routable addresses, so their queries meet the split-default route and enter
// the TUN where tun2socks.go's interceptor sees them. macOS has no Enforcer at
// all yet ([E9], bacchus#36), so the window's "saved for later use" notice
// already covers the whole section rather than this one field.
//
// A bool rather than the sentence itself so the sentence can stay a literal at
// its call site: clients/fyne/translations_test.go walks the AST for lang.L
// keys, and a key it cannot see is a label that silently ships untranslated.
func DNSCaptureIsComplete() bool { return true }

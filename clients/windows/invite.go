//go:build windows

// Invite QR window (issue #32): renders an already-minted coldstart invite
// string (core/coldstart.Invite, produced out of band by the operator's
// cmd/coldstart-issue — see that command's doc comment) as a scannable QR
// code, so it can be handed to a new user in person instead of copy-pasted.
// Client-side generation + display only: no new secret is minted here, and
// nothing is sent over the network — see docs/design/client-connection-ui.md.
package main

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"strings"
	"sync"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	qrcode "github.com/skip2/go-qrcode"
)

// qrPixels is the rendered QR image's edge length. Large enough to scan
// comfortably off a laptop screen at arm's length; the window sizes around it.
const qrPixels = 320

// canonicalizeInvite validates a pasted bacchus1:… string by round-tripping
// it through coldstart's own decode/encode (core/coldstart/secret.go) and
// returns the canonical form to encode as a QR. Round-tripping — rather than
// QR-encoding the pasted text verbatim — means stray whitespace or line
// breaks from a copy-paste (common when the string wraps in a terminal)
// can't end up baked into the code; DecodeInvite would already reject those,
// but re-encoding also normalizes anything it doesn't (e.g. surrounding
// spaces trimmed below).
func canonicalizeInvite(pasted string) (string, error) {
	trimmed := strings.TrimSpace(pasted)
	if trimmed == "" {
		return "", errEmptyInvite
	}
	inv, err := coldstart.DecodeInvite(trimmed)
	if err != nil {
		return "", fmt.Errorf("not a valid Bacchus invite: %w", err)
	}
	return coldstart.EncodeInvite(inv)
}

var errEmptyInvite = fmt.Errorf("paste an invite string first")

// inviteQRImage renders s as a PNG-encoded QR code and decodes it back to an
// image.Image, ready for walk.NewBitmapFromImage. Split from the walk glue so
// it's testable without a display (invite_test.go).
func inviteQRImage(s string) (image.Image, error) {
	png, err := qrcode.Encode(s, qrcode.Medium, qrPixels)
	if err != nil {
		return nil, err
	}
	return decodePNG(png)
}

func decodePNG(b []byte) (image.Image, error) { return png.Decode(bytes.NewReader(b)) }

var (
	inviteMu   sync.Mutex
	inviteOpen bool
)

// openInviteDialog is the tray menu's "Show invite QR…" handler. Like
// openSettingsDialog, it must run on its own locked OS thread (see
// runLockedToOSThread's doc comment in main.go).
func openInviteDialog() {
	inviteMu.Lock()
	if inviteOpen {
		inviteMu.Unlock()
		return
	}
	inviteOpen = true
	inviteMu.Unlock()
	defer func() {
		inviteMu.Lock()
		inviteOpen = false
		inviteMu.Unlock()
	}()

	var dlg *walk.Dialog
	var pasteEdit *walk.TextEdit
	var genBtn, closeBtn *walk.PushButton
	var statusLbl *walk.Label
	var qrView *walk.ImageView

	err := Dialog{
		AssignTo:      &dlg,
		Title:         "Bacchus — Invite QR",
		DefaultButton: &genBtn,
		CancelButton:  &closeBtn,
		MinSize:       Size{Width: qrPixels + 40, Height: qrPixels + 220},
		Layout:        VBox{},
		Children: []Widget{
			Label{Text: "Paste an invite string (from cmd/coldstart-issue, shared with you out of band):"},
			TextEdit{
				AssignTo: &pasteEdit,
				VScroll:  true,
				MinSize:  Size{Height: 60},
			},
			PushButton{AssignTo: &genBtn, Text: "Generate QR"},
			Label{AssignTo: &statusLbl, Text: ""},
			ImageView{AssignTo: &qrView, MinSize: Size{Width: qrPixels, Height: qrPixels}},
			Composite{
				Layout:   HBox{MarginsZero: true},
				Children: []Widget{HSpacer{}, PushButton{AssignTo: &closeBtn, Text: "Close"}},
			},
		},
	}.Create(nil)
	if err != nil {
		return
	}

	genBtn.Clicked().Attach(func() {
		canon, err := canonicalizeInvite(pasteEdit.Text())
		if err != nil {
			statusLbl.SetText(err.Error())
			return
		}
		img, err := inviteQRImage(canon)
		if err != nil {
			statusLbl.SetText("QR generation failed: " + err.Error())
			return
		}
		bmp, err := walk.NewBitmapFromImage(img)
		if err != nil {
			statusLbl.SetText("QR display failed: " + err.Error())
			return
		}
		_ = qrView.SetImage(bmp)
		statusLbl.SetText("Scan with the new client's camera, or share the image directly.")
	})
	closeBtn.Clicked().Attach(func() { dlg.Cancel() })

	dlg.Run()
}

module github.com/bacchus-vpn/bacchus

go 1.26.4

require (
	fyne.io/fyne/v2 v2.8.0
	github.com/flynn/noise v1.1.0
	github.com/getlantern/systray v1.2.2
	github.com/godbus/dbus/v5 v5.2.2
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/pion/dtls/v3 v3.1.4
	github.com/pion/ice/v4 v4.2.7
	github.com/pion/stun/v3 v3.1.6
	github.com/pion/turn/v4 v4.1.4
	github.com/pion/webrtc/v4 v4.2.16
	github.com/refraction-networking/utls v1.8.2
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	golang.org/x/crypto v0.49.0
	golang.org/x/net v0.52.0
	golang.org/x/sys v0.46.0
	golang.org/x/time v0.15.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
)

require (
	fyne.io/systray v1.12.2 // indirect
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/anthonynsimon/bild v0.14.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fredbi/uri v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/fyne-io/gl-js v0.2.1-0.20260315212741-029c47fd27e8 // indirect
	github.com/fyne-io/glfw-js v0.4.0 // indirect
	github.com/fyne-io/image v0.1.1 // indirect
	github.com/fyne-io/oksvg v0.2.0 // indirect
	github.com/getlantern/context v0.0.0-20190109183933-c447772a6520 // indirect
	github.com/getlantern/errors v0.0.0-20190325191628-abdb3e3e36f7 // indirect
	github.com/getlantern/golog v0.0.0-20190830074920-4ef2e798c2d7 // indirect
	github.com/getlantern/hex v0.0.0-20190417191902-c6586a6fe0b7 // indirect
	github.com/getlantern/hidden v0.0.0-20190325191715-f02dbb02be55 // indirect
	github.com/getlantern/ops v0.0.0-20190325191751-d70cb0d6f85f // indirect
	github.com/go-gl/gl v0.0.0-20260331235117-4566fea9a276 // indirect
	github.com/go-gl/glfw/v3.4/glfw v0.1.0-pre.1.0.20260707082822-2a407d02d01a // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/go-text/render v0.2.1 // indirect
	github.com/go-text/typesetting v0.3.4 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hack-pad/go-indexeddb v0.3.2 // indirect
	github.com/hack-pad/safejs v0.1.0 // indirect
	github.com/jeandeaual/go-locale v0.0.0-20250612000132-0ef82f21eade // indirect
	github.com/jsummers/gobmp v0.0.0-20230614200233-a9de23ed2e25 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e // indirect
	github.com/mattn/go-runewidth v0.0.24 // indirect
	github.com/nfnt/resize v0.0.0-20180221191011-83c6a9932646 // indirect
	github.com/nicksnyder/go-i18n/v2 v2.5.1 // indirect
	github.com/oxtoacart/bpool v0.0.0-20190530202638-03653db5a59c // indirect
	github.com/pion/datachannel v1.6.2 // indirect
	github.com/pion/interceptor v0.1.45 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.1.0 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.16 // indirect
	github.com/pion/rtp v1.10.2 // indirect
	github.com/pion/sctp v1.10.3 // indirect
	github.com/pion/sdp/v3 v3.0.19 // indirect
	github.com/pion/srtp/v3 v3.0.12 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	github.com/pion/turn/v5 v5.0.10 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rymdport/portal v0.4.2 // indirect
	github.com/srwiley/oksvg v0.0.0-20221011165216-be6e8873101c // indirect
	github.com/srwiley/rasterx v0.0.0-20220730225603-2ab79fcdd4ef // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	github.com/yuin/goldmark v1.8.2 // indirect
	golang.org/x/image v0.24.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gopkg.in/Knetic/govaluate.v3 v3.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Patched to randomize the DTLS handshake Random (drop gmt_unix_time); see
// third_party/pion-dtls/PATCHES.md and docs/adr/0018 (issue #57).
replace github.com/pion/dtls/v3 => ./third_party/pion-dtls

// Patched to let the reality client optionally tolerate a non-verifying TLS 1.3
// CertificateVerify signature, scoped to a single opt-in Config field; see
// third_party/utls/PATCHES.md and docs/adr/0032 (issue #92).
replace github.com/refraction-networking/utls => ./third_party/utls

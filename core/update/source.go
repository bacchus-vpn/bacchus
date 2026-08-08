package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ManifestName and BlobDir are the only two names a source has to know.
//
// A source is a plain byte store with one document and a content-addressed blob
// space: `<root>/manifest.json` and `<root>/blobs/<sha256 hex>`. That layout is
// not part of the signed object and is not a trust decision — the manifest names
// hashes and never locations (ADR-0052 §1) — it is a convention so that a mirror,
// a static host and a directory on a USB stick can all be populated the same way
// and none of them needs to know anything about releases.
//
// Because the blob name IS the digest, a mirror serving several releases holds
// them side by side with no per-release layout, and a blob two releases share is
// stored once.
const (
	ManifestName = "manifest.json"
	BlobDir      = "blobs"
)

// Source is where bytes come from. It is an interface because WHERE is not a trust
// decision: the manifest is self-authenticating and the artifact is
// content-addressed, so a hostile source can serve stale bytes or none, and never
// a forgery.
//
// That is the whole reason this seam exists rather than a fetch written into the
// updater. ADR-0052 §2 named a peer courier, a mirror, a static host, GitHub
// Releases, a Telegram bot and a USB stick as equally acceptable sources; a design
// where any of those is a special case would have made the first one shipped into
// the trusted one by accident.
type Source interface {
	// Manifest returns the signed bundle bytes.
	Manifest(ctx context.Context) ([]byte, error)
	// Artifact opens the bytes for a. The caller closes the reader and is
	// responsible for verifying them — no implementation of this interface is
	// trusted to have checked anything.
	Artifact(ctx context.Context, a Artifact) (io.ReadCloser, error)
	// String describes the source for a log line. It must not include a credential
	// and, for a remote source, should be short enough to read.
	String() string
}

// maxManifestBytes bounds the bundle. A manifest is a few hundred bytes per
// artifact row; 1 MiB is four orders of magnitude of headroom and still refuses an
// endless stream from a source that has decided to send one.
const maxManifestBytes = 1 << 20

// DirSource reads a source layout from a local directory.
//
// This is the sideload path, and it is not a lesser one: removable media, an
// operator drop, an artifact copied in by any means at all. It is also the shape a
// peer courier would land behind (ADR-0037's "dispense, never author"), which is
// why the interface is the same.
type DirSource struct{ Dir string }

func NewDirSource(dir string) *DirSource { return &DirSource{Dir: dir} }

func (d *DirSource) String() string { return "dir:" + d.Dir }

func (d *DirSource) Manifest(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(d.Dir, ManifestName))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readCapped(f, maxManifestBytes)
}

func (d *DirSource) Artifact(ctx context.Context, a Artifact) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// a.Name() is hex of a digest, so it cannot escape the directory whatever the
	// manifest said. filepath.Join would sanitise anyway; the guarantee is upstream.
	return os.Open(filepath.Join(d.Dir, BlobDir, a.Name()))
}

// ErrInsecureSource reports a source URL that would put the fetch in the clear.
var ErrInsecureSource = errors.New("update: source URL is not https")

// HTTPSource reads a source layout from a base URL.
//
// # Why https is required, when the bytes are signed anyway
//
// Integrity does not need it: the manifest is signed and the artifact is
// content-addressed, so a plaintext fetch cannot be substituted, only observed.
// EXPOSURE is the reason. A cleartext GET names the exact release being fetched to
// anyone on the path, which is a durable, greppable statement that this address
// runs this software — and this project spent three slices and two ADRs
// (ADR-0059, ADR-0062) removing the last cleartext surface a client had. Adding
// one back beside it, for a fetch that has no confidentiality requirement of its
// own, would be spending that work for nothing.
//
// Loopback is exempt so tests and a local mirror do not need a certificate. That
// exemption is checked against the parsed HOST, not against a prefix of the
// string, and it is re-checked on every redirect.
type HTTPSource struct {
	// Base is the source root. `<Base>/manifest.json` and `<Base>/blobs/<hex>`.
	Base string
	// Client is the HTTP client. Nil uses a shared default with a timeout, a
	// redirect check and no cookie jar.
	Client *http.Client
}

// userAgent is fixed and CARRIES NO VERSION.
//
// Carrying one would tell whoever runs a mirror which release each fetching
// address is on — a fleet inventory, handed over on every check, by the mechanism
// whose entire purpose is to fix nodes that are behind. The constant is honest
// rather than disguised: a node's fetch is not covert (it is infrastructure, and
// ADR-0052 §2 says so), and a client's rides inside its own tunnel, so there is
// nobody this string would be hiding from who is not already looking at the
// tunnel.
const userAgent = "bacchus-update"

var defaultHTTPClient = &http.Client{
	Timeout: 10 * time.Minute,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("update: too many redirects")
		}
		// A redirect is a source's decision, and a source is untrusted. It may not use
		// that to downgrade the hop out of TLS.
		return checkSourceURL(req.URL)
	},
}

func NewHTTPSource(base string) (*HTTPSource, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil {
		return nil, fmt.Errorf("update: parse source URL: %w", err)
	}
	if err := checkSourceURL(u); err != nil {
		return nil, err
	}
	return &HTTPSource{Base: strings.TrimSuffix(u.String(), "/")}, nil
}

// checkSourceURL enforces the scheme rule. Loopback is decided from the parsed
// host — "127.0.0.1", "::1", or the name "localhost" — never from a substring of
// the URL, because `http://localhost.example.net/` is not loopback and
// `http://evil/?x=127.0.0.1` is not either.
func checkSourceURL(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("%w: %s://%s (only https, or http to loopback, may carry a release fetch)", ErrInsecureSource, u.Scheme, u.Host)
	default:
		return fmt.Errorf("%w: scheme %q", ErrInsecureSource, u.Scheme)
	}
}

func (h *HTTPSource) String() string { return h.Base }

func (h *HTTPSource) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return defaultHTTPClient
}

func (h *HTTPSource) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.Base+"/"+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := h.client().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		// The status only. Not the body: a source is untrusted and its error page is
		// attacker-chosen text that would otherwise land in an operator's log.
		return nil, fmt.Errorf("update: %s: HTTP %d", path, resp.StatusCode)
	}
	return resp, nil
}

func (h *HTTPSource) Manifest(ctx context.Context) ([]byte, error) {
	resp, err := h.get(ctx, ManifestName)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return readCapped(resp.Body, maxManifestBytes)
}

func (h *HTTPSource) Artifact(ctx context.Context, a Artifact) (io.ReadCloser, error) {
	resp, err := h.get(ctx, BlobDir+"/"+a.Name())
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// readCapped reads at most max bytes and reports an error if there were more,
// rather than silently returning a truncated document that would then fail a
// signature check with a misleading reason.
func readCapped(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w: over %d bytes", ErrMalformed, max)
	}
	return b, nil
}

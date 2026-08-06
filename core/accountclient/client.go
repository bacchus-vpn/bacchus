package accountclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bacchus-vpn/bacchus/core/devicestore"
)

// Config builds a Client.
type Config struct {
	// BaseURLs are the account service's addresses, each scheme and authority
	// only — "https://host:port". They are supplied by whoever configured this
	// installation and are never discovered: the service is reached through the
	// onboarding endpoint's payment-only proxy or from inside a paid tunnel,
	// and a client that went looking for it on the open internet would be
	// designing for the one ingress path the deployment model says does not
	// exist.
	//
	// At least one is required. Empty is not an error at this layer — it is a
	// deployment with no account service, which New refuses so the caller does
	// not construct a client that can never work. Callers decide "no account
	// service" by not calling New.
	//
	// # Several addresses, one service
	//
	// This is a list of LOCATIONS, not of services (bacchus#192). The service
	// runs on anonymously rented infrastructure and its address will change; a
	// successor provisioned before the move is what makes a planned move
	// survivable, because a device that cannot reach this service has only the
	// renewal margin — six hours, not the 42-hour renewal period — before it
	// stops connecting.
	//
	// Every address shares ONE Audience and ONE pinned ServerCAFile, and that is
	// what keeps a second address a second location and never a second authority:
	// there is no per-address CA and no per-address audience to configure, so a
	// list of addresses cannot quietly become a list of trust roots. An address
	// that does not present the pinned identity fails its TLS handshake and is
	// treated as unreachable, exactly as an address that is down is.
	//
	// The order is the preference order. A whole exchange is run against one
	// address, and an address that fails as unreachable is set aside for
	// unreachableCooldown before it is preferred again — the ordering core's
	// coordinator pool uses on the same problem.
	BaseURLs []string

	// Audience is the service's own identity, bound into every assertion this
	// client signs. Pinned here, out of band, alongside ServerCAFile. It applies
	// to every address in BaseURLs and is validated once. It is never in any
	// response and MUST NOT be inferred from one.
	Audience string

	// ServerCAFile is a PEM file holding the certificate authority (or the
	// self-signed leaf) that authenticates the service's TLS identity. REQUIRED,
	// applied to every address in BaseURLs, and the system's public root pool is
	// deliberately not consulted even as a fallback.
	//
	// This is a security requirement rather than a convenience: the service sits
	// behind a camouflaged front under a name chosen to be unremarkable, so
	// requiring a publicly-trusted certificate for that name is a reachability
	// liability and buys nothing — the public CA system would authenticate the
	// name, and the name is a decoy. Pinning authenticates the service.
	ServerCAFile string

	// Timeout bounds one HTTP round trip. Zero uses DefaultTimeout.
	Timeout time.Duration

	// HTTPClient, when set, is used verbatim and ServerCAFile is NOT applied to
	// it — a caller supplying a transport owns its trust configuration. For
	// tests, and for an embedder that routes this traffic through something of
	// its own. A production caller should leave it nil.
	HTTPClient *http.Client

	// Logf, when set, receives this client's own diagnostics: the one or two
	// things that go wrong without failing the operation they happened during.
	// Nil discards them.
	//
	// Nothing written here carries a claim code, a credential, a recovery token
	// or a device public key. Those are what this surface exists to move and
	// what its own transport specification forbids recording; a diagnostic that
	// quoted one would put it in a log file that outlives the exchange.
	Logf func(format string, args ...any)
}

// DefaultTimeout bounds one round trip to the account service. Generous, because
// this traffic may be travelling through a camouflaged transport and a tunnel
// before it reaches anything, and nothing a user is waiting on blocks behind it:
// renewal runs in the background and enrollment happens once.
const DefaultTimeout = 30 * time.Second

// Client speaks the three verbs. Safe for concurrent use.
type Client struct {
	bases    []string
	audience string
	http     *http.Client
	log      func(format string, args ...any)

	healthMu  sync.Mutex
	unhealthy map[string]time.Time
}

// unreachableCooldown is how long an address that failed as unreachable is
// deprioritized for. It is core's coordCooldown, for core's reason: an address
// that is cooling down is still tried when every address is cooling down, since
// a slow retry beats a client that refuses to try at all.
//
// It is short relative to the ten minutes between renewal attempts, so it does
// almost nothing across renewals and everything within one exchange — the second
// leg of a challenge/verb pair must not open by preferring the address whose
// first leg just failed.
const unreachableCooldown = 30 * time.Second

// baseOrder returns the configured addresses healthy-first: the ones that have
// not failed recently in configured order, then the cooling ones in configured
// order.
//
// This is the ordering core's rankCoordinators gives the coordinator pool, on
// the same problem — several addresses for one thing, any of which may be
// blocked or gone, none of which may be dropped permanently. It is written here
// rather than called there because rankCoordinators is unexported in package
// core and this package deliberately does not pull the engine in; the two want to
// be one helper, and folding them is a change to a file this did not own. What is
// NOT different is the discipline: healthy-first, cooldown-sinks-never-removes,
// configured order preserved inside each group.
func (c *Client) baseOrder() []string {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	now := time.Now()
	healthy := make([]string, 0, len(c.bases))
	cooling := make([]string, 0, len(c.bases))
	for _, b := range c.bases {
		if t, bad := c.unhealthy[b]; bad && now.Sub(t) < unreachableCooldown {
			cooling = append(cooling, b)
		} else {
			healthy = append(healthy, b)
		}
	}
	return append(healthy, cooling...)
}

// markUnreachable sinks an address that did not answer.
func (c *Client) markUnreachable(base string) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	c.unhealthy[base] = time.Now()
}

// overExchanges runs one whole exchange against each configured address in
// health order, stopping at the first address that does not fail as unreachable.
//
// A WHOLE exchange, not a single request, and that is the load-bearing part. A
// challenge is server state — the service holds live challenges in memory, which
// is why a restart answers unknown_challenge — so a challenge minted at one
// address means nothing at another. Rotating between the two legs of a pair would
// turn "the first address went away" into a permanent unknown_challenge loop.
//
// It rotates only on ErrUnreachable. Everything else is the service ANSWERING,
// and a coded refusal is the same answer at every address of one service: moving
// on would turn one refusal into as many refusals as there are addresses, each
// spending a challenge, and for the verbs that spend more than a challenge it
// would be far worse (see Enroll, which does not use this).
func (c *Client) overExchanges(exchange func(base string) error) error {
	order := c.baseOrder()
	var err error
	for _, base := range order {
		err = exchange(base)
		if !errors.Is(err, ErrUnreachable) {
			return err
		}
		c.markUnreachable(base)
		if len(order) > 1 {
			c.logf("account service: %s did not answer, trying the next configured address", base)
		}
	}
	return err
}

func (c *Client) logf(format string, args ...any) {
	if c.log != nil {
		c.log(format, args...)
	}
}

// New validates cfg and builds a Client.
//
// It refuses rather than defaults on all three of the pinned values, and the
// refusals are the point:
//
//   - No BaseURLs at all would build a client that fails on first use with a URL
//     parse error instead of at configuration time.
//   - An empty Audience would sign assertions bound to the empty string, which
//     every service would accept from every other service's device. The account
//     service refuses to start without one for the same reason.
//   - An empty ServerCAFile would fall back to the public root pool, silently
//     turning a pinned channel into one any publicly-trusted certificate can
//     terminate. That failure is invisible: everything works, against whoever is
//     in the middle.
//
// The last two are validated ONCE, for the whole list, because there is one of
// each: they are what make an additional address a second location rather than a
// second authority (bacchus#192). Only the first refusal changed when the field
// became a list — from "BaseURL is required" to "at least one".
//
// http:// is refused outright. The assertions authenticate this client to the
// service and cover no response byte, so everything valuable on this surface —
// the credential, the issuer cert, the admission credential — travels back
// unprotected without TLS, and an attacker who suppressed a valid enrollment
// would simply complete it and keep the result.
func New(cfg Config) (*Client, error) {
	var bases []string
	seen := map[string]bool{}
	for _, raw := range cfg.BaseURLs {
		trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
		if trimmed == "" {
			continue
		}
		u, err := url.Parse(trimmed)
		if err != nil {
			return nil, fmt.Errorf("accountclient: BaseURL %q: %w", raw, err)
		}
		if u.Scheme != "https" {
			return nil, fmt.Errorf("accountclient: BaseURL %q must be https, got %q", raw, u.Scheme)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("accountclient: BaseURL %q has no host", raw)
		}
		if u.Path != "" && u.Path != "/" {
			// The verb paths are absolute ("/v1/enroll"); a base with a path would
			// silently drop it and dial the wrong place, or produce "/prefix/v1/…"
			// against a service that serves neither. Refusing beats guessing.
			return nil, fmt.Errorf("accountclient: BaseURL %q must be scheme and host only, got path %q", raw, u.Path)
		}
		// Deduplicated in configured order, the way core dedups its coordinator
		// pool: the same address twice is not a second location, and it would make
		// one unreachable address consume two rotations.
		if s := u.String(); !seen[s] {
			seen[s] = true
			bases = append(bases, s)
		}
	}
	if len(bases) == 0 {
		return nil, errors.New("accountclient: at least one BaseURL is required")
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		return nil, errors.New("accountclient: Audience is required; an empty one binds assertions to nothing")
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	hc := cfg.HTTPClient
	if hc == nil {
		if strings.TrimSpace(cfg.ServerCAFile) == "" {
			return nil, errors.New("accountclient: ServerCAFile is required; this service's TLS identity is pinned out of band and the public root pool is never used")
		}
		pem, err := os.ReadFile(cfg.ServerCAFile)
		if err != nil {
			return nil, fmt.Errorf("accountclient: read ServerCAFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			// Named without quoting the file's contents back, matching how the
			// rest of this project reports a bad key file.
			return nil, fmt.Errorf("accountclient: ServerCAFile %s held no PEM certificate", cfg.ServerCAFile)
		}
		hc = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    pool,
					MinVersion: tls.VersionTLS12,
				},
				// This client makes at most three short requests per exchange and
				// then goes quiet for hours. Keeping a pool of idle connections
				// open to the account service is a persistent, distinctive flow
				// for no gain.
				MaxIdleConns:    2,
				IdleConnTimeout: 30 * time.Second,
			},
			// A redirect is a way to move a request off the host whose identity
			// was pinned, and none of these verbs has any reason to be
			// redirected. Refusing turns that into a legible failure instead of
			// a silently relocated enrollment.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("account service redirected; refusing to follow")
			},
		}
	}

	return &Client{
		bases:     bases,
		audience:  strings.TrimSpace(cfg.Audience),
		http:      hc,
		log:       cfg.Logf,
		unhealthy: map[string]time.Time{},
	}, nil
}

// Audience is the pinned service identity this client signs against. Exposed so
// a caller can show what it is configured to trust without holding a second copy
// of the string.
func (c *Client) Audience() string { return c.audience }

// maxResponseBytes caps what this client will read from a response. The bodies
// here are three short strings; anything larger is either a different service or
// something trying to make this process the resource it exhausts.
const maxResponseBytes = 1 << 20

// challengeResponse is the /v1/challenge body. []byte decodes from the padded
// standard base64 encoding/json produces on the other side, so one encoding
// spans this document and the signed bodies it carries.
type challengeResponse struct {
	Challenge []byte    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

// credentialsResponse is the shape BOTH issuing verbs answer with. One struct,
// because they are one shape and two would be two places to notice a field.
//
// It stays a wire type of this package's own rather than decoding straight into
// devicestore.Credential, which happens to hold the same three strings: the
// on-disk record and the response body are two formats that agree today and are
// versioned by two different documents, and a shared struct would make the next
// field this service adds a change to what a device persists.
type credentialsResponse struct {
	Device     string `json:"device"`
	Admission  string `json:"admission"`
	IssuerCert string `json:"issuer_cert"`
}

// credential is what the caller gets: the wire response as the thing a device
// stores. Nothing is re-encoded on the way — see devicestore's record doc.
func (r credentialsResponse) credential() devicestore.Credential {
	return devicestore.Credential{Device: r.Device, IssuerCert: r.IssuerCert, Admission: r.Admission}
}

type enrollRequest struct {
	Claim     string `json:"claim"`
	DevicePub []byte `json:"device_pub"`
	Label     string `json:"label"`
	Challenge []byte `json:"challenge"`
	Sig       []byte `json:"sig"`
}

type credentialRequest struct {
	DevicePub []byte `json:"device_pub"`
	Challenge []byte `json:"challenge"`
	Sig       []byte `json:"sig"`
	// CurrentCred and CurrentIssuerCert are deliberately absent. The service
	// resolves the account by public key and has no parameter for them; a field
	// the service ignores is a field that will eventually be trusted by mistake.
}

// Challenge fetches a fresh nonce from POST /v1/challenge.
//
// The returned expiry is ADVISORY and this package treats it as such: the
// service's answer is authoritative, and a caller must handle unknown_challenge
// on the following request whatever this field said. It is returned because a
// caller with a clock badly out of step can notice it, not because anything here
// decides on it.
//
// Fetching a challenge mints server state and spends nothing of the caller's, so
// this is the one verb here that is freely retryable.
//
// It rotates over the configured addresses, and the challenge it returns belongs
// to whichever one answered. A caller that follows it with a signed verb must
// send that verb to the SAME address, which is why every such caller in this
// package drives the rotation itself (overExchanges) rather than calling this.
func (c *Client) Challenge(ctx context.Context) (challenge []byte, expiresAt time.Time, err error) {
	err = c.overExchanges(func(base string) error {
		challenge, expiresAt, err = c.challengeFrom(ctx, base)
		return err
	})
	return challenge, expiresAt, err
}

func (c *Client) challengeFrom(ctx context.Context, base string) ([]byte, time.Time, error) {
	var resp challengeResponse
	if err := c.post(ctx, base, "/v1/challenge", struct{}{}, &resp); err != nil {
		return nil, time.Time{}, err
	}
	if len(resp.Challenge) == 0 {
		return nil, time.Time{}, fmt.Errorf("%w: /v1/challenge returned no challenge", ErrUnreachable)
	}
	return resp.Challenge, resp.ExpiresAt, nil
}

// post sends one JSON request and decodes one JSON response.
//
// Every failure that is not a coded refusal is wrapped in ErrUnreachable,
// including a body this client could not parse and a bare status with no error
// envelope. That is the specification's rule about interference: only a
// well-formed error body is a statement by the service, and everything else — a
// truncated response, a TLS failure, a timeout, a 404 from something that is not
// the account service — is the network, not an answer.
// base names which configured address to send to; the caller owns that choice
// because it owns the exchange the request belongs to.
func (c *Client) post(ctx context.Context, base, path string, req, out any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("accountclient: encode %s request: %w", path, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("accountclient: build %s request: %w", path, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Deliberately no User-Agent, no Accept-Language, no custom header. Every
	// one of them is a distinguishing byte on a surface whose whole point is
	// being unremarkable, and none of them changes an answer.
	httpReq.Header.Set("User-Agent", "")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrUnreachable, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("%w: %s: read response: %w", ErrUnreachable, path, err)
	}

	if resp.StatusCode != http.StatusOK {
		return decodeError(path, resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		// A 200 whose body does not parse is not the service answering. It is
		// what a captive portal, a proxy error page, or a truncated stream looks
		// like from here.
		return fmt.Errorf("%w: %s: response did not parse", ErrUnreachable, path)
	}
	return nil
}

// errorEnvelope is the whole of the service's error body. There is no message
// field on the wire and this struct must not grow one: a message is where an
// implementation leaks the thing the code was chosen to withhold.
type errorEnvelope struct {
	Error struct {
		Code         Code `json:"code"`
		RetryAfterMS int  `json:"retry_after_ms"`
	} `json:"error"`
}

// decodeError turns a non-200 into either a coded refusal or an ErrUnreachable.
//
// The distinction is load-bearing and it is exactly the one the specification
// draws for a client that cannot tell an old deployment from a censor: a 404
// carrying {"error":{"code":"unknown_verb"}} means "this deployment does not
// implement this yet", and a BARE 404 means something in the path is answering
// on the service's behalf. The first is a fact about the deployment; the second
// must never be allowed to disable a feature permanently.
func decodeError(path string, status int, raw []byte) error {
	var env errorEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Error.Code == "" {
		return fmt.Errorf("%w: %s: HTTP %d with no error envelope", ErrUnreachable, path, status)
	}
	return &Error{
		Code:       env.Error.Code,
		Status:     status,
		RetryAfter: time.Duration(env.Error.RetryAfterMS) * time.Millisecond,
		Recognized: known[env.Error.Code],
		Verb:       path,
	}
}

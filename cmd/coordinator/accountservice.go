package main

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// The account service's address in the signed cold-start directory (issue #193,
// ADR-0061; ADR-0016 decision 4 in bacchus-payment is what asks for it).
//
// The desktop client holds the account service's address in a static JSON file
// and has no channel of any kind for learning that it changed. The service runs
// on anonymously rented infrastructure and its address WILL change, and because
// a device renews as soon as it enters its renewal margin, an unplanned move
// takes the first devices offline about six hours later — not the forty-two
// between renewals. This is the one artifact a client already fetches, verifies
// and could re-fetch after a move, so it is where the address goes.
//
// What is published is a LOCATION, never a trust root. The client keeps the
// audience it binds assertions to and the CA it pins the service's TLS identity
// against, both configured out of band and neither derivable from anything here
// — see coldstart.Entry.Role and core/accountclient.New, which validates those
// two once for a whole address list precisely so that adding an address adds a
// place and not an authority.

// accountServiceFlags collects the -account-service occurrences.
//
// It is a package-level value populated by flag.Var — the shape
// -admission-authority already uses — so buildSnapshot reads it the way it reads
// operators: written once during flag parsing, before any goroutine that reads
// it starts, and never mutated after.
//
// REPEATABLE, and that is not a convenience. ADR-0016 decision 3 gave the client
// a LIST precisely so a planned move is survivable: the successor address is
// provisioned before the move and the client rotates to it by itself. The
// directory's list is what SUPERSEDES a client's configured one, so a
// coordinator that could publish only one address would narrow every client that
// adopted its directory from two addresses to one — the change would take away
// the redundancy it exists to generalise.
type accountServiceFlags []string

func (f *accountServiceFlags) String() string { return strings.Join(*f, " ") }

// Set validates one occurrence and appends it.
//
// Every refusal is a flag-parse error, which is fatal, and that is the same
// discipline -operators, -geoip and -country-overrides take: an operator who
// asked for an address to be published must not get a coordinator that came up
// looking configured while publishing nothing — or publishing something no
// client can use.
//
// The checks are core/accountclient.New's own, applied here so a typo fails in
// the operator's terminal rather than in every client that adopts this
// directory. A client cannot refuse one bad entry without refusing the good ones
// beside it — accountclient validates the whole list at construction, so a
// single unusable address would cost a client every address it was given — which
// makes the one place a human is looking the cheapest place to be strict.
func (f *accountServiceFlags) Set(v string) error {
	// TrimRight of "/" before parsing, matching accountclient.New: an operator
	// who writes the address with a trailing slash has named the same location,
	// and a base URL with a path is refused two checks below.
	raw := strings.TrimRight(strings.TrimSpace(v), "/")
	if raw == "" {
		return errors.New("-account-service: empty value")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("-account-service %q: %w", v, err)
	}
	if u.Scheme != "https" {
		// http would put the credential travelling back to the client on the
		// open wire; accountclient refuses it outright and so does this.
		return fmt.Errorf("-account-service %q must be https, got %q", v, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("-account-service %q has no host", v)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		// The verb paths are absolute ("/v1/credential"), so anything here is
		// either dropped silently or concatenated into a path the service does
		// not serve. Refusing beats guessing.
		return fmt.Errorf("-account-service %q must be scheme and host only", v)
	}
	s := u.String()
	if slices.Contains(*f, s) {
		// The same address twice is not a second location, and it would make one
		// unreachable address consume two of a client's rotations.
		return nil
	}
	*f = append(*f, s)
	return nil
}

// accountServices is what -account-service collected. Empty is the default and a
// complete deployment: a network that runs no account service publishes no
// "account" entry, and a client then falls back to whatever its own config names
// — which is every client built before this existed.
var accountServices accountServiceFlags

// accountServiceEntries renders the configured addresses as directory records.
//
// ID is the URL's HOST rather than a shared "account" tag. Nothing keys on it
// today, but several records sharing one id is a directory nobody can refer to
// an entry of, and the host is the one value already unique per entry (Set
// rejects the same address twice).
//
// It reads accountServices without the registry lock, unlike everything else
// buildSnapshot touches: this slice is written once by flag parsing and the
// registry maps are written by the packet loop. Taking mu around a read of an
// immutable value would suggest it protects something.
func accountServiceEntries() []coldstart.Entry {
	if len(accountServices) == 0 {
		return nil
	}
	out := make([]coldstart.Entry, 0, len(accountServices))
	for _, base := range accountServices {
		id := base
		if u, err := url.Parse(base); err == nil && u.Host != "" {
			id = u.Host
		}
		out = append(out, coldstart.Entry{Role: "account", ID: id, Addr: base})
	}
	return out
}

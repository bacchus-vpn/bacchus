# 55. The 1.0 country picker: capacity without latency, a list fetched outside a session, and busy shown before the click

- Status: accepted
- Date: 2026-08-03

## Context

`clients/fyne` is the only desktop client (ADR-0039, bacchus#138) and it ships
with **one button**. Its own source said so — *"Still no country picker"* — and
`Controller.connectAsync` left `core.Config.Geo` unset, which makes `core`
resolve the country itself and take the first one the coordinator reports as
assignable (`core`'s `pickCountry`). A user found out where they had egressed by
checking their apparent IP afterwards.

The whole of what this product promises is that you choose the jurisdiction you
appear from, and no shipping client could express it. bacchus#16 is that card and
it is the last v1 client feature.

Three things made it more than a widget:

- **`core.Engine.ListCountries` requires the client role and a started engine**,
  and this client builds an engine only at connect time. A picker needs the list
  **before** the connect.
- **`core.CountryInfo.PingMs` exists, is `omitempty`, and is always 0.** The
  card's title asks for ping. The field is an unfed seam on the coordinator side
  too, and `TestCountryReplyWireContract` pins it absent from the wire while
  unfed.
- **`pickCountry` uses a configured country VERBATIM even when the list says it
  is busy or absent.** That is deliberate and is not this lane's to change:
  substituting a different country for the one the user asked for would silently
  egress them somewhere they did not choose.

## Decision 1 — the list is fetched by a throwaway client-role engine

`appstate.FetchCountries` builds a `core.Engine` with the coordinators, the
client role and the admission anchor, starts it, calls `ListCountries`, and stops
it. Nothing binds: `SocksAddr` is unset and `core` only listens inside `Connect`.
No serve roles, no transport pool, no relay chaining — none of them changes the
answer to "which countries exist".

This is the **third** instance of one pattern rather than a new one:
`cmd/node`'s `-list` does exactly this, and the retired Windows tray client's own
picker did too (`listCountries`, deleted in bacchus#138). The two alternatives
were considered:

| alternative | why not |
| --- | --- |
| hold one long-lived engine open from launch, and list through it | An engine is not free to hold: it keeps a UDP socket per coordinator open for the life of the app, whether or not anybody ever presses anything, and it would have to be rebuilt on every settings change. It also puts a second engine in the process whose lifetime is not the session's, next to the `gen` machinery that exists precisely because two engines at once is where this client's worst bug lived. |
| have `Connect` publish the list it already fetches | It only fetches one when no country is configured (`resolveCountry`), so the moment a user picks a country the list stops being refreshed — the picker would go stale exactly for the users who use it. And a list that only arrives during a connect cannot populate a picker the user is choosing from before connecting. |

The admission anchor **is** passed even though a list verifies no exit, so a
malformed anchor fails the picker in the same breath it would fail the connect
rather than leaving a populated list and an unexplained refusal behind it.

## Decision 2 — no latency in 1.0

**Ruled by the owner, 2026-08-03.** The picker is country + busy. `PingMs` stays
on the wire, unread.

The coordinator's own comment already rejected the tempting server-side source:
deriving it from that coordinator's RTT to each exit measures
coordinator-to-exit latency, which is not the quantity the user is choosing on,
and *"a plausible-looking wrong number is worse than a blank"*. The client-side
sources are no better, and each costs something this project spends effort not
spending:

| source | what it costs |
| --- | --- |
| this client's own past sessions | a file on disk recording **which countries this person has connected to** — a device-seizure artifact, in a censored country, bought for a decorative number |
| in-memory only, this run | a number for the one country you already connected to, and a blank for every other row: useless for choosing, and inconsistent down the list |
| probe the signed directory's exits | builds a network map on the client and generates traffic to every exit — the thing ADR-0042 §9 exists to prevent |
| aggregated client reports | needs a reporting path that does not link a client to the countries it asks about. That path does not exist. |

So the honest 1.0 picker is **country + busy**, which is complete on its own: the
user's question is "can I get out through Germany", and `Available`/`Exits`
answers it. The wire field is kept so a client can render it the day a reporting
path exists; a card is filed for that day.

What survives of the card's "busy bar" is the **counts**, which are the whole of
what the wire carries about a country's shape. They are rendered as text and not
as a bar, on ADR-0039's own reasoning: the state indicator is *"the single most
important widget in the app"*, and a row of coloured bars in the centre of the
window competes with it for the one glance a stressed user has.

## Decision 3 — busy is made visible before the click, never substituted after it

`core`'s refusal to substitute is the property; the picker's job is to make the
refusal predictable, and nothing more:

- Every country the coordinator offers gets a row, including the full ones. A
  busy country is **greyed** (`widget.LowImportance`, which resolves to
  `theme.ColorNameDisabled`) and says "busy" in a word.
- A busy country stays **selectable**. Making it unselectable would take away a
  user's ability to insist on a jurisdiction and be told the honest reason it did
  not work, which is the same trade `pickCountry` refuses.
- When the **chosen** country is busy or missing from the list, the picker says
  so under the list, before the click.
- The chosen country always has a row even when the current list does not offer
  it — including when there is no list at all. Dropping it would move the
  selection to something else, which is the substitution this whole feature
  exists to refuse, performed by the UI instead of by `core`.

A country tag that is not a country code is refused rather than defaulted:
`ValidateCountry` fails the connect naming the value, one round trip earlier than
the coordinator would. A hand-edited `"country": "Germany"` canonicalizes to
nothing, and treating nothing as "let core choose" would connect the user
somewhere while their config file still named a country they believe they are in.

## Decision 4 — the picker shows the DERIVED country, and shows no apparent IP

**Derived**, per the owner's ruling of 2026-08-03 and ADR-0042 §8: the `countries`
reply is a per-country **aggregate**, so there is no "declared country" of a
country to put beside it — the disagreement bacchus#113 carries is per-exit and
this list is per-country. The user's question is "how will sites treat me", which
is exactly the derived value. Nothing about the picker changes when bacchus#113
lands.

**No apparent IP**, which the card also asks for. The only way a client learns
its apparent address is to ask a third party over the tunnel, and that:

- tells that third party an exit is carrying a client right now, and does it on
  every connect;
- adds a fixed external endpoint this client must reach — a new fingerprint and
  a single address a censor can block, in an app whose entire design routes
  around exactly that (`core/geoip`'s "why local, never a lookup service" is the
  same argument one layer up);
- buys nothing the user can act on. A chosen country is **guaranteed** by
  Decision 3: `core` uses it verbatim and the coordinator refuses rather than
  substituting, so a connect that succeeded in DE is in DE. The address would
  only re-state it.

The picker therefore states the chosen country and leaves the address alone.

## Decision 5 — the two refusals are said in the user's own language

The wire distinguishes `country-busy` from `no-such-country` specifically so a
client can (`cmd/coordinator`'s `assignRefusal`), and until now this client
discarded the distinction by relaying `core`'s sentence — which contains the
words "exit" and "quota", in English, to an audience this client is translated
for.

`appstate.DetailFor` now classifies those two into a `Detail{Kind, Country}`, and
`clients/fyne` renders each from a `lang.L` literal the translation test's AST
walk can see. Everything else is still relayed verbatim: `core`'s errors are not
fixed sentences and have no translation to look up, and replacing them with a
generic translated one would throw away the only diagnostic a user has.

That classification is a coupling to another package's message text — the same
coupling `relayChainFailedPrefix` already was — and it is paid for the same way:
`controller_test.go` drives a real `core.Engine` against a coordinator that
refuses, and fails if what lands on the detail line is not the plain-language
sentence. A reword in `core` goes red instead of silently reverting a
user-facing message to protocol vocabulary.

## Consequences

- **A user can choose a country.** First time on any shipping client.
- `Config` gains `country`, written to the same file the Settings window writes.
  Two writers of one file means the Settings window can no longer be seeded from
  a copy taken when it opened — it re-reads at save time, or a save half an hour
  later reverts a country chosen in between, from a window that has no control
  for it and so could not show what it undid.
- `Controller.SetConfig` closes a gap that predates the picker: the Settings
  window wrote to disk and told `main.go`, and nothing told the `Controller`, so
  a coordinator, DNS or kill-switch change did not reach a connect until restart.
- The picker is **inert while a session is up**. `core` settles the country once
  per engine so a reconnect cannot move a user between jurisdictions mid-session;
  a picker that accepted a change would show one country while traffic left
  through another. It says "disconnect first" instead.
- **The list is refreshed at launch, on the Refresh button, and after a settings
  save — never on a timer.** Polling would generate a periodic, fixed-interval
  request to the coordinator from every idle client, which is both a load
  question and a traffic-shape question, and neither is answered here.
- A failed refresh **keeps the previous list**. A coordinator going away does not
  make the countries it named a minute ago stop existing, and an empty picker
  takes away the ability to choose at the moment the app can least explain
  itself.
- **What is not built:** any latency figure (above); the apparent IP (above); a
  country control in the Settings window (the jurisdiction is the headline
  choice, not a preference to go looking for behind a menu); and `Engine.Country`
  — with "Automatic" chosen, `core` picks the country and this client has no
  accessor to ask which one it picked, so the picker says "Automatic" rather than
  naming it. `core` announces it on the detail line as it always has.

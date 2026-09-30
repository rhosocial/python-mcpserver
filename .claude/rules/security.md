# Security Rules

Each rule below is a decision with a reason. Changing one without the reason
opens a hole that no test will catch, because the test asserts the behaviour,
not the threat.

---

## 1. Verify locally, never by introspection (unless the caller opts in)

A service verifies the access token's **signature, `iss`, `aud` and `exp`
locally** against a cached JWKS. It does not call the authorization server on
every request.

Introspection (RFC 7662) as a per-request step would make the AS a network
dependency of every tool call in every service. That is the bottleneck the
whole design exists to avoid.

The consequence is accepted deliberately: a revoked access token lives for at
most its remaining TTL (5–15 minutes). Services needing immediate revocation
for a high-risk operation add an introspection side channel **themselves**;
this library does not provide it, because a library-level default would apply
it to every call including reads.

## 2. Asymmetric algorithms only, by default

A JWKS distributes public keys. Accepting `HS256` in that position lets an
attacker sign a token with the public key as the HMAC secret.

`allowed_algorithms` defaults to `("ES256", "RS256", "EdDSA")`. A deployment
that genuinely needs something else must set it explicitly, which puts the
decision in the diff.

`none` is never accepted. There is no configuration that enables it.

## 3. A `kid` miss refreshes the JWKS at most once per cooldown

Key rotation publishes a new `kid`.  A verifier that only refreshes on a miss
handles it; one that never refreshes rejects every token signed after the
rotation.

The per-kid cooldown stamp is written **before** the fetch, not after its
outcome is known.  That ordering is what makes the burst case work: fifty
requests racing a rotation all miss, and the first to reach the lock stamps
`kid` and fetches; the other forty-nine find the stamp and go straight to
re-reading a cache the first one has already replaced.  Stamping afterwards
lets all fifty fetch, because none of them has finished yet.

The cooldown is seconds.  The cost of a short one is bounded and named: a
rotation that *republishes* a `kid` within the cooldown can be missed for that
long.  Nothing else is a trade-off here.

## 4. A fetch failure with a cached key set is not a failure

If the JWKS has been fetched before and the last refresh attempt failed, the
cached set is still used — **even past its TTL**.  Only having *nothing* cached
is an error.

The alternative is that every token in the fleet is rejected for as long as the
AS is unreachable: with a 15-minute access token, a two-minute AS outage logs
every user out of every service behind it.  That is a far worse failure than
the one this rule accepts.

Serving a stale key set does not extend anybody's access.  **A key set and a
grant are different things.**  Revoking a grant does not remove a key from the
JWKS — it stops the AS minting new access tokens with it.  A token accepted
against a stale key set is still bounded by its own `exp` and still confined to
this one service by its `aud`.

The exposure this does buy: if the AS rotated **and** is unreachable, tokens
signed by the retired key stay acceptable until it returns.  That window is
bounded by `max_ttl_seconds`, which is why the ceiling clamp on a
server-requested `max-age` is a security control rather than hygiene — and why
`JwksCache.invalidate()` exists for an operator who cannot accept even that.

## 5. `aud` is checked, and it is the isolation boundary

`aud` defaults to the service's own `resource` URL. A token minted for
`calendar` is rejected by `contact-manager` — not because of table prefixes or
separate databases, but because `aud` does not match.

This is why table prefixes are defence in depth rather than the boundary. Any
downstream change that relies on the prefix for isolation has misread the
design.

## 6. Scope is checked per tool, at the ASGI layer

`AuthSettings.required_scopes` stays **empty**. The SDK's requirement is
all-or-nothing, which would refuse a read-only token from the read tools as
well.

The check runs as pure ASGI middleware, not a `ServerMiddleware`, because only
the ASGI layer can produce an HTTP status. A `ServerMiddleware` raises inside
dispatch, and the client sees a JSON-RPC error under a `200` — which no client
can act on.

A token that fails to resolve is passed through untouched, so every 401 — with
its `WWW-Authenticate` challenge — stays in the SDK's hands. This middleware
only ever produces 403.

## 7. The scope vocabulary is declared once

`ResourceServerConfig.scopes` is the single source. It feeds both the per-tool
check and the PRM document's `scopes_supported`.

Two hand-maintained lists drift, and the drift is invisible: the document
advertises a scope the server does not accept, or worse, the server accepts one
the document never promised. A client that trusted the document then gets an
unexpected 403.

## 8. Identity is never a parameter

No public function, MCP tool or CLI command takes `user_id` or `principal_id`.
Identity comes from `current_principal()`, which reads a request-scoped
`ContextVar` populated by the SDK's own auth middleware.

A parameter is a value a caller can choose. Identity is not a choice.

## 9. The projection is a projection

`<prefix>_principals` holds `central_user_id` plus service-private attributes.
It has no password, no email, no credential of any kind.

If a downstream service needs the display name, it calls the identity service —
or does not. Copying profile data into the projection converts it into a second
source of truth that drifts.

## 10. Revoking authorization does not delete data

Three independent state machines, never collapsed into one flag:

| Machine | Where | Revoked means |
|---|---|---|
| grant (authorization) | AS | no new access tokens; existing ones expire within TTL |
| principal (projection) | local DB | row is retained; re-granting restores access |
| central user (account) | AS | a separate, explicit action |

The user-facing consequence, and the reason this is written down: revoking a
service's authorization must not destroy that service's data. Only an explicit
delete request does that.

# Rate limiting

Investigation for [#71](https://github.com/alveusgg/census/issues/71): account + IP keyed rate limiting, prompted by security probing against the deployed API. Verified against `main` at `ef6c107`. Nothing is implemented yet; this is the assessment and a proposed plan.

## State of play

The API has no rate limiting of any kind. There is no `@fastify/rate-limit` dependency, no hand-rolled limiter, and no attempt throttling on any credential check.

The blocking problem is not the missing limiter, it is that IP keying cannot work correctly today. `census/api/src/index.ts` creates Fastify with only `routerOptions`, so `trustProxy` defaults to `false`. Behind Cloudflare (proxied CNAME, `infrastructure/pulumi/resources/API.ts`) and Azure Container Apps ingress, `request.ip` resolves to the ingress peer, so in production every request already looks like the same address. A limiter keyed on `request.ip` would behave as a single global bucket and the first attacker to trip it would deny service to everyone.

`trustProxy: true` is not the fix either: Cloudflare appends to `X-Forwarded-For` rather than replacing it, so the leftmost entry is attacker-controlled and rotating it per request lands each request in a fresh bucket. `CF-Connecting-IP` is the right value, but it is only trustworthy once the origin is locked to Cloudflare, because the Container Apps default hostname is independently reachable and an attacker can set the header directly there. So the correct trust configuration depends on the real production header chain, which has to be measured, and on origin lockdown, which is infrastructure work.

## Entry points, by abuse risk

The auth resolves the user inside the tRPC `procedure` middleware (`census/api/src/trpc/trpc.ts`), after a JWKS verification and a DB lookup. So at HTTP-hook time we know the IP but not the user, and by the time we know the user the expensive work is already done.

Ranked for an attacker actively probing:

- **Critical, `feed.subscribeToRequestsForFeed` / `feed.completeCaptureRequest`** (`census/api/src/api/feed.ts`). Both are `publicProcedure`. Authorisation is a shared key compared with a plaintext `target.key !== key` in `census/api/src/services/feed/index.ts`, with unlimited attempts, no lockout, no logging, and an error that names which feeds failed. A guess yields presigned S3 upload URLs. Needs constant-time comparison, a generic error, and an attempt lockout, not just rate limiting.
- **Critical, public SSE subscriptions** (`capture.live.capture`, `users.live.recentAchievements`, `users.live.levelUps`). Each holds a long-lived connection and a Postgres listener. The load report (`docs/dev/api/sse-scalability-load-report.md`) shows this is memory-bound. A requests-per-minute limit does not help, since an attacker opening connections slowly stays under it; this needs a concurrent-connection cap, which is a separate control.
- **High, `/auth/*`** (`census/api/src/services/auth/router.ts`). `POST /auth/refresh` forwards an arbitrary token to the upstream Alveus identity provider; the other routes trigger upstream work and a user upsert. Abuse costs the shared IdP, so this wants the strictest bucket.
- **High, `GET /rest/profile`** (`census/api/src/rest/profile.ts`). Unauthenticated, one DB query per hit, and a clean username-enumeration oracle (404 vs 200). Likely serves a Twitch chat bot from a fixed IP, so it is the clearest allowlist case.
- **High, authenticated tRPC procedures.** Every call costs a JWKS verification plus a DB round trip before the handler runs. `observation.list` is the worst amplifier: `Pagination.size` (`census/api/src/api/observation.ts`) is `z.number().default(30)` with no upper bound, so `size: 1000000` is valid input.
- **Medium, `POST /discord/interactions`** (`census/api/src/rest/discord.ts`). Verifies an Ed25519 signature before doing work, so it is well defended and only needs the global bucket.
- **Medium, `GET /readyz`.** Unauthenticated DB round trip per call; exclude from limiting (probes hit it every few seconds) but debounce the result.

Also flag: `createGuidesRouter` (`census/api/src/api/guides.ts`) is not mounted, but contains `publicProcedure` mutations. Mounting it as written would ship unauthenticated database writes.

## Infrastructure

There is no Redis or Valkey anywhere, local (`local/core-services.yml` runs Postgres and MinIO only) or in production (`infrastructure/pulumi`). The existing `KVCache` is unsuitable as a counter store: Cloudflare KV is eventually consistent with a 60s TTL floor, and Postgres KV would add a DB write to the hot path we are trying to shed.

Production runs `min: 1, max: 1` with `sessionAffinity: false`, so the API is single-instance and an in-memory store is correct for a first pass, not a compromise. The moment `scale.max` goes above 1, every in-memory limit silently divides by the replica count, so that step needs either a shared store or a guard that fails loudly.

## Recommended approach

Put `@fastify/rate-limit` at the HTTP layer as the outer shield, with a key generator that uses the account when a well-formed token is present and falls back to IP, keeping anonymous and authenticated as separate buckets and never letting a forged token reach a more permissive bucket than the anonymous IP floor. This is the only layer that runs before the expensive auth work and the only one that covers `/auth/*` and `/rest/*`, which is where the probing lands. A tRPC middleware layer for per-procedure, per-account precision on the expensive procedures is a good second pass once the outer layer is proven, since `httpBatchLink` means one HTTP request can carry many procedure calls.

429 responses should send `Retry-After` and the `RateLimit-*` headers (which must be added to the CORS `exposedHeaders` list in `census/api/src/index.ts`), and the body must stay generic so the limiter is not itself an enumeration oracle. tRPC needs a `TooManyRequestsError` added to `shared/errors/index.ts`. Durable banning belongs at Cloudflare, not the origin; the API's job is to emit the signal.

## Plan

Phase 1, assessment fixes and a basic limiter (no new infrastructure):

- [ ] Measure the real production `X-Forwarded-For` chain and record it here
- [ ] Set `trustProxy` explicitly based on that measurement, with a `clientIp()` helper preferring `CF-Connecting-IP`
- [ ] Open a follow-up for Cloudflare origin lockdown; note that IP keying is best-effort until it lands
- [ ] Add `@fastify/rate-limit`, registered before the route plugins, with separate anonymous/authenticated buckets
- [ ] Strict buckets on `/auth/*` and `/rest/profile`; global default on tRPC; exempt `/healthz` and `/readyz`
- [ ] Add `TooManyRequestsError`; add `Retry-After` and `RateLimit-*` to CORS `exposedHeaders`; keep 429 bodies generic
- [ ] Environment-driven allowlist for the chat bot and feed clients
- [ ] Bound `Pagination.size` with `.max()`
- [ ] Constant-time feed key comparison with a generic error and an attempt lockout
- [ ] Decide `createGuidesRouter`: fix the public mutations or document why it stays unmounted
- [ ] Tests: normal traffic passes, over-limit is rejected with correct headers, buckets are independent, allowlist bypasses, keys are not spoofable via `X-Forwarded-For`

Phase 2, shared store and per-route tuning (triggered by `scale.max > 1` or by phase 3 data):

- [ ] Startup guard failing loudly if `scale.max > 1` while the in-memory store is active
- [ ] Choose the shared store (Valkey, or a dedicated unlogged Postgres counter table); rule out Cloudflare KV and the existing `KVCache` hot path
- [ ] tRPC middleware for per-procedure limits on `observation.list`, `guides.utils.unfurl`, `twitch.clip`, `twitch.vod`
- [ ] SSE concurrent-connection cap, per key and process-wide, sized from the load report
- [ ] Client: no React Query retry on `TOO_MANY_REQUESTS`; explicit backoff for `httpSubscriptionLink` reconnects so a 429 does not become a retry storm
- [ ] Tune buckets against real traffic

Phase 3, monitoring and alerting (using the existing Sentry / OpenTelemetry setup):

- [ ] Replace the empty `onError() {}` on the tRPC plugin so transport failures stop being discarded
- [ ] Emit a metric on every limit hit, tagged with route and key type; add span attributes matching the existing `flagOperationCache` pattern
- [ ] Alert on sustained 429s from distinct keys, on the SSE ceiling being approached, and on failed feed-key attempts crossing a threshold
- [ ] Feed confirmed abusive sources into Cloudflare WAF rules

## Open questions

1. What is the real production `X-Forwarded-For` shape? Everything about the key generator depends on it, and only someone with prod access can measure it.
2. Is Cloudflare already caching `/rest/profile`, given it sends `Cache-Control: public, max-age=60`?
3. Which IPs does the chat bot call `/rest/profile` from, and are they stable enough to allowlist?
4. Is `scale.max > 1` planned soon? If so, the shared store moves into phase 1.
5. Does the probing traffic have an identifiable signature? A Cloudflare WAF rule would be a faster stopgap than any origin change.

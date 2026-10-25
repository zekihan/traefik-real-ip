# OPS-16: downstream replay after panics

## Decision status

Proposed safe policy: invoke downstream at most once per middleware call. On panic, propagate the original
panic to the enclosing server/recovery layer without replay, response rewriting, or body reconstruction.
Apply this to every method, including GET: the middleware cannot know whether a handler committed an action.
Cancellation, body rewindability, and an apparently unwritten response are not proof that retrying is safe.

Maintainer agreement to change the deliberate retry compatibility has **not** been obtained. The implementation
therefore exposes this behavior as `panicPolicy: propagate`, retaining `legacy-retry` as the default and treating
an empty value as legacy compatibility. Invalid values fail initialization. The opt-in is testable without
changing live configuration. A default switch, retry removal, or operator rollout remains a separate decision.
**OPS-16 remains unresolved for default/legacy configurations:** installing this version alone does not prevent
replay. Keeping legacy behavior avoids silently removing retries that an operator may depend on, but retains
duplicate-action and consumed-body risks. Choosing propagation trades those retries for visible abort/error
semantics; it cannot undo an action already committed downstream or prevent an outer layer from retrying.

## Operator migration checklist (proposal; no rollout authorized)

1. Obtain maintainer/operator agreement on the target policy and affected routes. Inventory outer recovery,
   proxy/client retry behavior, and reliance on existing abort retries; do not infer safety from the HTTP method.
2. In an approved disposable Traefik/Yaegi setup, explicitly set `panicPolicy: propagate`. Use synthetic POST
   actions to verify one downstream invocation, ordinary/abort and interpreter-wrapped panics, consumed bodies,
   cancellation, and partial responses over HTTP/1 and HTTP/2 with the intended recovery chain.
3. Validate provider startup separately: an unavailable/invalid enabled provider must fail initialization;
   after restoring only the fixture, a later initialization must recover with the intended trusted ranges.
   Do not disable trust providers or relax `denyUntrusted` to make the migration pass.
4. Before any separately approved rollout, record expected abort/error responses, an owner, monitoring of
   downstream invocation counts and errors, and a rollback decision. Omitting the setting or selecting
   `legacy-retry` restores replay behavior and its risks; rollback is not evidence that replay is safe.

## Synthetic observations

`TestPanicPolicy_RequestReplay` uses POST requests with a synthetic body, an in-memory action counter, and
an in-memory response recorder. Every handler increments the counter before panicking. Both explicit legacy
and omitted policy are tested. The table records invocation counts; the action count equals the invocation count.

| Scenario | Legacy invocations / result | Propagate invocations / result |
| --- | --- | --- |
| Fully consumed body, ordinary panic | 2; bodies `payload`, empty; `200 completed` | 1; original panic escapes; no response written |
| Fully consumed body, abort | 2; bodies `payload`, empty; `200 completed` | 1; original abort escapes; no response written |
| Partially consumed body, ordinary panic | 2; bodies `pay`, `loa`; `200 completed` | 1; body `pay`; original panic escapes |
| Partial response, ordinary panic or abort | 2; committed `202 partial:` becomes `202 partial:completed` | 1; original panic escapes; `202 partial:` stays unchanged |
| Context canceled immediately before ordinary panic or abort | 2; both handler observations are canceled; `200 completed` | 1; canceled context preserved; original panic escapes |
| Abort on every invocation | 5 (`MaxRetryCount + 2`); final abort escapes; no response written | 1; original abort escapes |
| Starting beyond the abort retry limit | 2; direct final downstream call still runs; `200 completed` | 1; original abort escapes |

The POST request is never rebuilt. Legacy retries see the same consumed body. The repeated-abort test records
an exhausted body on every call after the first. An HTTP recorder initializes its status to 200 even when
nothing was written; this is **not** evidence of a successful HTTP response after a propagated panic.

`TestPanicPolicy_PropagateHTTPResponse` uses a disposable local HTTP/1 server and a synthetic POST for both
ordinary panics and `http.ErrAbortHandler`. It confirms exactly one downstream invocation in each case:

- With no headers written, the client receives a connection error and no HTTP response.
- After flushing `202` and `partial:` with a longer declared content length, the client receives those
  status/body bytes followed by `io.ErrUnexpectedEOF`. No replacement body is appended.

These are local Go HTTP server observations, not a reproduction of production impact or a claim about every
Traefik protocol/recovery configuration. The middleware preserves panic identity, including interpreter wrappers;
any enclosing recovery layer owns its treatment of that value.

`TestPanicPolicy_ProviderInitializationRecovery` combines both enabled providers with local fixtures. A partial
Cloudflare load returns no middleware and makes no downstream call. Once the fixture becomes complete, a later
`New` succeeds and ordinary/abort panics follow the selected policy: one call with propagation, two with legacy
or the default. The recovered handler still resolves the synthetic client through the provider's trusted range.

## Remaining acceptance

Before changing the default, a maintainer must agree whether abort retries were deliberate compatibility and
approve the migration policy. Proposed recommendation: make `propagate` the default in an agreed compatibility
release, document the change, then remove legacy replay separately if approved.

Live Traefik/Yaegi acceptance is unverified. A separately approved disposable setup should check ordinary panics,
abort sentinels (including interpreter wrapping), outer recovery middleware, HTTP/1 and HTTP/2 partial responses,
cancellation, and invocation counts. No live proxy, provider, production service, or user app calls are needed
for the local regression suite. The repository Docker wrapper uses fixed shared container/network names and
cleanup, so it is not run on this shared Mac.

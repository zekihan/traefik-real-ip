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

## Remaining acceptance

Before changing the default, a maintainer must agree whether abort retries were deliberate compatibility and
approve the migration policy. Proposed recommendation: make `propagate` the default in an agreed compatibility
release, document the change, then remove legacy replay separately if approved.

Live Traefik/Yaegi acceptance is unverified. A separately approved disposable setup should check ordinary panics,
abort sentinels (including interpreter wrapping), outer recovery middleware, HTTP/1 and HTTP/2 partial responses,
cancellation, and invocation counts. No live proxy, provider, production service, or user app calls are needed
for the local regression suite. The repository Docker wrapper uses fixed shared container/network names and
cleanup, so it is not run on this shared Mac.

# Fuzzing campaign

Native Go fuzzing of the request-identity paths of the plugin. The threat model: an attacker controls
every request header and the immediate peer address (`RemoteAddr`) but not the trusted-proxy
configuration. The primary bug class is client IP spoofing: attributing a request to an address the
attacker chose although it arrived through an untrusted hop, or trusting a header that should be ignored.
Panics, unbounded allocation or CPU on hostile headers, and accepting malformed IPs or CIDRs are also in
scope.

All targets live in `_test.go` files, so non-test code stays stdlib-only and Yaegi-compatible.

## Reference model

`fuzz_reference_test.go` is an independent model of the documented behavior (README). It shares no
parsing or containment code with production:

- its own address grammar: RFC 4291 section 2.2 IPv6 text forms (with embedded dotted quads) and strict
  dotted-quad IPv4, no zones;
- trust containment through `net/netip` prefixes, with IPv4-mapped IPv6 prefixes normalised to IPv4 so
  `::ffff:10.0.0.0/104` and `10.0.0.0/8` match the same peers;
- the legacy resolution order (`Cf-Connecting-Ip` → `Eo-Connecting-Ip` → `X-Real-IP` →
  `X-Forwarded-For`, headers only consulted for trusted peers), the right-to-left `X-Forwarded-For` walk
  (first untrusted hop from the right, else the leftmost hop), header limits (32 hops, 4096 bytes, 45 bytes
  for single-IP headers), and the outgoing `X-Forwarded-For` in append and replace mode;
- the scoped-trust rules (`refScoped` in `fuzz_scoped_test.go`).

## Targets and properties

| Target | File | Input | Properties checked |
| --- | --- | --- | --- |
| `FuzzLegacyResolve` | `fuzz_legacy_test.go` | peer, trusted CIDRs, the four identity headers (single or repeated lines), mode / abort flags | Full `ServeHTTP` vs reference: status, `X-Real-IP` (canonical, single value), `X-Is-Trusted`, outgoing `X-Forwarded-For` in append and replace mode. Independent provenance oracle: a client other than the peer must come from an identity header of a trusted peer, and an `X-Forwarded-For` client must have only trusted hops on its right. An untrusted peer is always attributed to itself. The abort-retry path keeps the same identity. |
| `FuzzForwardedForChain` | `fuzz_legacy_test.go` | byte string selecting hops from a pool of trusted, look-alike (`::a01:203`, `64:ff9b::`, `2002::`, `::ffff:0:x`), untrusted and malformed entries, plus surrounding whitespace | Trust walk vs reference; the result is never left of an untrusted hop; equivalent spellings of the chain (OWS, IPv4-mapped, expanded / upper-case IPv6) resolve identically. |
| `FuzzRawHTTPRequest` | `fuzz_legacy_test.go` | raw HTTP/1.1 request bytes parsed with `http.ReadRequest` | Reference agreement on whatever `net/http` accepts; debug log output stays bounded and never echoes long raw header values; re-encoding with different header-name case and optional whitespace gives the same identity output. |
| `FuzzScopedResolve` | `fuzz_scoped_test.go` | peer from each trust class, identity headers, edge secret, 8 config variants (edge auth on/off, `denyUntrusted`, Cloudflare/forwarded overlap) | Reference agreement: `Cf-Connecting-Ip` only from Cloudflare peers (with a valid edge secret when configured), `Eo-Connecting-Ip` only from EdgeOne peers, `X-Real-IP` / `X-Forwarded-For` only from forwarded peers. All other identity headers and the secret header are stripped before `next`. Abort-retry keeps the identity. |
| `FuzzEdgeSecrets` | `fuzz_scoped_test.go` | secret file contents, presented value, repeat flag | Parser vs reference (at most 2 trimmed, nonempty secrets of at least 16 bytes, file at most 4 KiB). `verify` accepts only exactly one header value equal to a loaded secret. |
| `FuzzProviderCIDRs` | `fuzz_config_test.go` | provider response body | An accepted snapshot is nonempty, bounded, deduplicated, free of default routes (including mapped spellings) and equal to the reference parse. Any invalid entry rejects the whole response. |
| `FuzzSourceAddr` | `fuzz_config_test.go` | `RemoteAddr` string | A zone is accepted only after an IPv6 literal; the parsed peer equals the reference. |
| `FuzzConfigCIDRs` | `fuzz_config_test.go` | trusted ranges, modes, policies | `New` succeeds exactly for valid configurations. The resulting trust sets have the same membership as the reference prefixes, including IPv4-mapped spellings of ranges and addresses. |

Each target has hand-written seeds covering realistic and adversarial inputs. Examples are Cloudflare
and EdgeOne ranges from `remote_ips/`, mapped and NAT64 look-alikes, zones, ports, Unicode whitespace,
oversized headers, repeated header lines and malformed literals. The regression inputs in `testdata/fuzz/`
run as part of `go test`.

## Runs

Machine: Linux amd64, 16 cores, Go 1.27.3, shared with two other fuzzing jobs. Every run used
`-parallel 4`. The runs were sequential, so the cached corpus carried over between runs of the same target.

| Target | Runs | Total time | Total execs | Corpus | Last new coverage |
| --- | --- | --- | --- | --- | --- |
| `FuzzLegacyResolve` | 2m + 20m + 30m | 52 min | 46,182,632 | 414 | 28m45s into the 30m run (slow tail) |
| `FuzzRawHTTPRequest` | 2m + 20m + 30m | 52 min | 50,110,292 | 609 | 28m45s into the 30m run (mostly `net/http` parser paths) |
| `FuzzScopedResolve` | 2m + 20m | 22 min | 17,296,136 | 217 | 19m12s (6 entries in the last 5 min) |
| `FuzzForwardedForChain` | 20m | 20 min | 17,028,938 | 178 | 17m45s (1 entry in the last 5 min) |
| `FuzzSourceAddr` | 10m | 10 min | 12,081,348 | 72 | 9m51s |
| `FuzzConfigCIDRs` | 10m | 10 min | 10,870,375 | 205 | 8m48s |
| `FuzzEdgeSecrets` | 10m | 10 min | 8,547,416 | 122 | 7m18s |
| `FuzzProviderCIDRs` | 10m | 10 min | 3,998,938 | 197 | 9m45s |
| **Total** | | **186 min** | **166,116,075** | | |

Throughput was roughly 10k–15k execs/s per target on 4 workers; `FuzzProviderCIDRs` is slower (about
6.6k/s) because each input streams a full response through the parser. An earlier exploratory session on
another machine ran every target for 45 s. It is not counted above. That session found Finding 1 and three
harness bugs, which were fixed before these runs:

- peers with `[` in the zone vs `net.SplitHostPort`;
- non-token header names keep their case in `textproto`, so only identity output is compared;
- `X-Edge-Auth` is only stripped when edge auth is configured.

Their inputs are kept as regression seeds.

The slower-growing targets (`FuzzLegacyResolve`, `FuzzRawHTTPRequest`) were still adding corpus entries at
a low rate at the end. In `FuzzRawHTTPRequest` most of that is request-line and header-parsing coverage
inside `net/http`, not plugin code. No target produced a failure in any run.

## Findings

### 1. Unicode whitespace accepted around X-Forwarded-For entries (Low, fixed)

- **Reproducer:** a trusted peer (`192.0.2.1` with `192.0.2.0/24` trusted) sends
  `X-Forwarded-For: 198.51.100.66 , 192.0.2.2` (also `\u0085`, `　`, ` `, ...). `net/http`
  passes these bytes through as obs-text. Before the fix the request resolved to `198.51.100.66` with
  status 200; README says malformed entries return 400. Table cases are in
  `TestIPResolver_handleXForwardedFor` ("non-breaking space around entry", "next line before entry"). The
  `FuzzForwardedForChain` and `FuzzRawHTTPRequest` seeds also cover it.
- **Root cause:** `handleXForwardedFor` used `strings.TrimSpace` on each hop. That strips every Unicode
  space, not only the optional whitespace (SP, HTAB) allowed around list elements.
- **Impact:** not a spoofing vector. Only hops left of the trusted suffix are affected, and those are
  attacker-controlled anyway. The value selected is the same address the attacker could have sent
  without the extra characters. The bug is a validation gap that let malformed input through.
- **Fix:** `b3742e6` (Reject non-OWS whitespace around X-Forwarded-For entries) trims only `" \t"`.

No other crashers or property violations were found. There were no panics, no oracle disagreements and
no runaway allocation or timeouts. Header processing is bounded by the hop, byte and single-IP limits.

## Observations (deliberate or ambiguous behavior, not changed)

1. **Legacy mode leaves CDN and forwarding headers from untrusted peers in place.** In the default
   (non-scoped) mode an untrusted peer's `Cf-Connecting-Ip`, `Eo-Connecting-Ip`, `Forwarded` and
   `True-Client-Ip` reach the backend unchanged. The plugin ignores them, and `X-Real-IP`,
   `X-Forwarded-For` and `X-Is-Trusted` are always rewritten. Backends that read those headers directly
   can be spoofed. Scoped mode strips them. Worth a README note or an opt-in strip for legacy mode.
2. **Fail-open on unexpected panics under `legacy-retry`.** If a non-abort panic happened inside the
   plugin before the identity headers were rewritten, the default `legacy-retry` policy would call `next`
   with the original, unsanitised headers. No fuzz input triggered such a panic. See `docs/panic-replay.md`
   for the policy discussion.
3. **Multiple `X-Forwarded-For` lines return 400.** RFC 9110 treats repeated list-header lines as
   equivalent to one comma-joined line. The plugin rejects them by design rather than guessing the order.
4. **In append mode with a CDN header, only the first `X-Forwarded-For` line is kept.** When
   `Cf-Connecting-Ip` / `Eo-Connecting-Ip` determines the client, the incoming `X-Forwarded-For` is not
   validated. Only its first line (`Header.Get`) is carried into the rewritten value, after the
   client-first reordering and deduplication.
5. **Single-IP headers accept special addresses.** From a trusted peer, `X-Real-IP` and
   `Cf-Connecting-Ip` accept `0.0.0.0`, `::`, multicast and `255.255.255.255`.
6. **Provider default-route check only rejects full default routes.** A `/0` or a mapped `/96` covering
   all IPv4 is rejected. Near-default ranges such as `0.0.0.0/1` or `::ffff:0:0/97` are accepted. Provider
   data is outside the attacker's control in this threat model.
7. **Leading zeros in CIDR prefix lengths.** `net.ParseCIDR` accepts `10.0.0.0/08`. The reference
   accepts this on purpose (`refParsePrefixLenient`) to match configuration parsing.
8. **RFC 7239 `Forwarded` is not parsed.** It is never used as an identity source; scoped mode strips it.
9. **Operator data trimming.** Provider response lines and edge-secret file lines use `strings.TrimSpace`,
   so Unicode spaces are trimmed there. This is operator- or provider-supplied data, so out of scope.

## Open questions

- Should legacy mode strip `Cf-Connecting-Ip`, `Eo-Connecting-Ip`, `True-Client-Ip` and `Forwarded`
  from untrusted peers, or at least say in the README that they pass through?
- Should repeated `X-Forwarded-For` lines be joined (RFC 9110 semantics) instead of rejected?
- Should the provider check also reject near-default ranges, for example any prefix shorter than /8 (IPv4)
  or /16 (IPv6)?
- Should single-IP headers reject unspecified, multicast and broadcast addresses?

## Rerunning

```bash
# Seed corpora and regression inputs only (part of `make test`)
go test -run Fuzz -count=1 .

# One target at a time (Go runs a single -fuzz target per invocation)
go test -run '^$' -fuzz '^FuzzLegacyResolve$' -fuzztime 20m -parallel 4 .
```

Target names: `FuzzLegacyResolve`, `FuzzForwardedForChain`, `FuzzRawHTTPRequest`, `FuzzScopedResolve`,
`FuzzEdgeSecrets`, `FuzzProviderCIDRs`, `FuzzSourceAddr`, `FuzzConfigCIDRs`.

The generated corpus is kept in the Go build cache (`$(go env GOCACHE)/fuzz`). When a run fails, Go
writes the input to `testdata/fuzz/<Target>/`. Commit it there, add a table test where practical, and
fix the cause.

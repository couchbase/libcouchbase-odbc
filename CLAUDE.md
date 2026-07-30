# CLAUDE.md — libcouchbase-odbc

Orientation + behaviour reference for this repo. Read this before grepping; it names the file to open
for each subsystem so you don't have to rediscover the layout.

## What this is

`libcouchbase` — the Couchbase **C** SDK ("LCB"), version **3.3.19** (`CMakeLists.txt:35`), forked as
`libcouchbase-odbc` and vendored into the Couchbase ODBC driver at `contrib/libcouchbase-odbc`.
C99 + C++11/14 internals behind a pure-C public API. Upstream JIRA project is `CCBC`; the ODBC fork's
own commits use `ODBCC-*`.

The fork exists to add things the ODBC driver / Power BI connector need — currently **JWT / OAUTHBEARER
authentication** (`ODBCC-59`, `ODBCC-67`). Everything else tracks upstream.

**The ODBC driver only uses a thin slice of this SDK** — the analytics query path. Verified by grepping
`driver/` in the parent repo, the entire surface it touches is:

```
lcb_createopts_create / _connstr / _credentials / _authenticator / _tls_key_password / _destroy
lcbauth_new / lcbauth_set_jwt / lcbauth_clone / lcbauth_unref
lcb_create → lcb_connect → lcb_wait → lcb_get_bootstrap_status
lcb_cmdanalytics_create / _payload / _callback / _destroy → lcb_analytics
lcb_respanalytics_status / _row / _is_final / _cookie / _error_context
lcb_errctx_analytics_statement / _first_error_message / _first_error_code
lcb_strerror_short / lcb_strerror_long, lcb_destroy
```

No KV, no N1QL/query, no search, no views, no subdoc. If a change is only about KV or query it cannot
affect the ODBC driver; if it touches `src/auth.cc`, `src/http/`, `src/analytics/`, `src/connspec.cc`,
`src/instance.cc`, or `src/bucketconfig/`, it can.

## Mental model

LCB is a **single-threaded, callback-oriented, event-loop-driven** library. There is no thread safety
inside an `lcb_INSTANCE`; concurrency is achieved by one instance per thread (see
`example/threads-private`) or by an instance pool (`example/instancepool`).

Everything is: build a **command** object → **schedule** it → **pump the loop** → your **callback**
fires → command completes. Nothing happens between `lcb_*` scheduling calls and `lcb_wait()`.

```c
lcb_CREATEOPTS *opts = NULL;
lcb_createopts_create(&opts, LCB_TYPE_CLUSTER);
lcb_createopts_connstr(opts, connstr, strlen(connstr));
lcb_createopts_credentials(opts, user, ulen, pass, plen);
lcb_create(&instance, opts);          /* parses connstr, builds settings; NO network I/O */
lcb_createopts_destroy(opts);

lcb_connect(instance);                /* schedules bootstrap */
lcb_wait(instance, LCB_WAIT_DEFAULT); /* runs the loop until bootstrap settles */
lcb_get_bootstrap_status(instance);   /* <- the real "did connecting work" answer */

/* ... schedule ops, lcb_wait() again ... */
lcb_destroy(instance);
```

Two gotchas that cause most "why is nothing happening" confusion:

- `lcb_create()` does **no** I/O. It only parses the connection string and populates `lcb_settings`.
  Argument errors surface here; connectivity errors surface from `lcb_get_bootstrap_status()`.
- `LCB_WAIT_DEFAULT` (0) returns early if bootstrap failed; `LCB_WAIT_NOCHECK` (1) drains the loop
  regardless. Use `NOCHECK` when you've already checked bootstrap status yourself
  (`include/libcouchbase/couchbase.h:1865`).

### Instance types

`LCB_TYPE_CLUSTER` (no bucket; cluster-level services — this is what analytics/ODBC uses) vs
`LCB_TYPE_BUCKET` (bucket-bound; required for KV). Set at `lcb_createopts_create()`.

## Source map

`src/README.md` has an upstream per-file listing — read it for the exhaustive version. The
directories, by what they *do*:

| Path | Responsibility |
|---|---|
| `include/libcouchbase/` | The entire public API. `couchbase.h` is the umbrella; `error.h`, `auth.h`, `cntl.h`, `iops.h` are the ones you'll actually open. |
| `src/instance.cc` | `lcb_create` / `lcb_destroy` / `lcb_connect`. Instance struct is `lcb_st` in `src/internal.h:115`. |
| `src/connspec.{cc,h}` | Connection-string parsing → `lcb::Connspec`. |
| `src/settings.{cc,h}` | `lcb_settings` — the resolved config every subsystem reads. |
| `src/cntl.cc` | `lcb_cntl()` / `lcb_cntl_string()` dispatch + the **string→setting table** (`~line 1060`). |
| `src/auth.cc`, `src/auth-priv.h` | `lcb::Authenticator`. Credentials, modes, JWT. |
| `src/bootstrap.{cc,h}` | Top-level "get me a cluster config" state machine + background polling. |
| `src/bucketconfig/` | The config *providers* (CCCP, HTTP, file, static) and `Confmon`, which cycles them. |
| `src/newconfig.cc` | *Applying* a new config (diffing servers, re-mapping vbuckets). |
| `src/vbucket/` | Raw vbucket-map parsing + key→vbucket→node hashing (ex-`libvbucket`). |
| `src/mc/`, `src/mcserver/` | Memcached (KV) packet building, scheduling, per-server connection state, SASL negotiation. |
| `src/lcbio/` | All socket I/O: connection establishment, read/write contexts, timers, connection pooling, TLS glue. Model-agnostic (event vs completion). |
| `src/http/` | User-level and service-level HTTP requests (`lcb_http`). This is the transport for query/analytics/search/views/management. |
| `src/lcbht/` | HTTP *response parser* (wraps `contrib/http_parser`). |
| `src/jsparse/` | Streaming JSON row parser — how query/analytics deliver rows incrementally. |
| `src/analytics/` | Analytics service: `analytics.cc` (entry points), `analytics_handle.{cc,hh}` (per-request state). |
| `src/n1ql/` | Query (N1QL) + prepared-statement cache + index management. |
| `src/search/`, `src/views/` | FTS and Views, same handle+parser shape as analytics. |
| `src/operations/` | KV op entry points (get, store, remove, counter, subdoc, observe, ping…). |
| `src/capi/` | `lcb_CMD*` / `lcb_RESP*` struct definitions — the concrete types behind the opaque public pointers. |
| `src/retryq.{cc,h}`, `src/retrychk.cc` | The retry queue and the "is this error retryable" policy. |
| `src/ssl/` | OpenSSL interfacing. |
| `src/netbuf/`, `src/rdb/` | Output buffer / pooled read buffer implementations. |
| `src/tracing/`, `src/metrics/` | OpenTelemetry-style spans and operation metrics. |
| `plugins/io/` | Event-loop backends: `libevent`, `libev`, `libuv`, `select`, `iocp` (Windows). |
| `contrib/` | Vendored: `cbsasl`, `cJSON`, `jsonsl`, `http_parser`, `snappy`, `lcb-jsoncpp`, `cliopts`, `gtest-1.8.1`, `HdrHistogram_c`. |
| `tools/` | The `cbc` CLI family (`cbc`, `cbc-pillowfight`, `cbc-n1qlback`, `cbc-subdoc`, `cbc-proxy`…). |
| `example/` | Runnable samples. `example/analytics-jwt/analytics_jwt_tls.cc` is the reference for the ODBC/JWT path. |

## Connection string

Parsed in `src/connspec.cc`. Shape:

```
scheme://host1,host2:port/bucket?opt=val&opt=val
```

Schemes — the authoritative list is `LCB_SPECSCHEME_*` in `src/connspec.h:225-232`, matched in
`src/connspec.cc:346-383`: `couchbase://` (KV, 11210), `couchbases://` (KV+TLS, 11207),
`http://` (HTTP bootstrap, 8091), `https-internal://` (HTTP+TLS, 18091),
`couchbase+explicit://`, `couchbase+dnssrv://`, `couchbases+dnssrv://`, `memcached://` (raw
memcached compat). Absent scheme is an error; an empty string defaults to `couchbase://` with
`localhost`. Note the TLS HTTP scheme is `https-internal://` — plain **`https://` is not a
scheme** and fails `lcb_create()` with `LCB_ERR_INVALID_ARGUMENT`.

A port given without an explicit `=type` inherits the scheme's implicit port type
(`connspec.cc:158-168`), so `couchbases://host:18443` registers 18443 as a **KV** endpoint and
leaves the HTTP bootstrap list empty. To bootstrap over HTTP on a non-default port, say so:
`couchbases://host:18443=https` or `https-internal://host:18443`. Exception: if the port equals
the scheme's implicit port it is treated as unspecified, and both bootstrap lists are populated
with their defaults.


Options the parser handles **specially** (`src/connspec.cc:213-320`):

| Key | Values |
|---|---|
| `bootstrap_on` | `cccp` \| `http` \| `all` \| `file_only` |
| `username` / `user`, `password` / `pass` | credentials inline in the connstr |
| `ssl` | `on` \| `off` \| `no_verify` \| `no_global_init` |
| `truststorepath`, `certpath`, `keypath` | TLS files; **require** an SSL scheme or SSL host, else parse error |
| `console_log_level` | integer log level |
| `log_redaction` | `on`/`true` \| `off`/`false` |
| `dnssrv` | `on`/`true` \| `off`/`false` — conflicts with a `+dnssrv` scheme |
| `ipv6` | `only` \| `disabled` \| `allow` |

**Every other `?key=value` is passed through to `lcb_cntl_string()`**, so the full option vocabulary is
the string table in `src/cntl.cc` (~line 1060) — `operation_timeout`, `analytics_timeout`,
`query_timeout`, `http_timeout`, `config_poll_interval`, `compression`, `retry_policy`,
`enable_collections`, `network`, `client_string`, `sasl_mech_force`, and ~70 more. That table is the
authoritative list; do not guess option names.

## Configuration / bootstrap behaviour

This is the part with the most emergent behaviour, so it's worth understanding rather than grepping.

A **cluster config** (topology + vbucket map + service ports) is fetched by one of several
**Providers**, coordinated by `Confmon` (`src/bucketconfig/clconfig.h`, `confmon.cc`):

| Provider | File | How |
|---|---|---|
| `CLCONFIG_CCCP` | `bc_cccp.cc` | Config over the KV (memcached) port. The default and preferred path. |
| `CLCONFIG_HTTP` | `bc_http.cc` | Streaming `/pools/default/bucketsStreaming/...` over 8091. Legacy fallback; also how a long-lived push channel is kept. |
| `CLCONFIG_FILE` | `bc_file.cc` | On-disk config cache (`config_cache` cntl). |
| `CLCONFIG_MCRAW` | `bc_static.cc` | Static host list, no real config (raw memcached mode). |
| `CLCONFIG_CLADMIN` | `bc_static.cc` | Cluster-admin bootstrap for `LCB_TYPE_CLUSTER`. |

`Confmon` keeps an ordered list of active providers and **cycles** through them: `refresh()` each in
turn until one yields a config, emitting `CLCONFIG_EVENT_GOT_NEW_CONFIG` /
`CLCONFIG_EVENT_GOT_ANY_CONFIG` / `CLCONFIG_EVENT_PROVIDERS_CYCLED`. `lcb::Bootstrap`
(`src/bootstrap.h`) is the `Listener` that reacts, and it also drives background polling
(`bgpoll()`, controlled by `config_poll_interval`).

When a config arrives, `Confmon` calls `config_updated()` on **every** enabled provider, and both
`HttpProvider` and `CccpProvider` respond by clearing their node list and rebuilding it from the
addresses advertised in that config (management endpoints for HTTP, data-service for CCCP). The
connection-string hosts are therefore discarded on the first config. That breaks reconnection when
the advertised addresses are not reachable — e.g. behind a load balancer, where alternate addresses
apply one external hostname to every service and inherit unlisted ports.
`LCB_CNTL_PIN_CONFIG_NODES` (connstr: `pin_config_nodes=true`) keeps the connection-string hosts
instead; off by default, and it affects only config retrieval, not service discovery.

Refreshes are **throttled** — `error_thresh_count` (`LCB_CNTL_CONFERRTHRESH`) and
`error_thresh_delay` (`LCB_CNTL_CONFDELAY_THRESH`) mean a burst of errors does not produce a burst of
config fetches. This is why "I forced an error and no refresh happened" is expected behaviour, not a
bug.

When a new config arrives, `src/newconfig.cc` diffs it against the current one and rewires server
connections. Operations affected by a topology change go through `src/retryq.cc`, gated by
`src/retrychk.cc` and the `retry_policy` / `retry_interval` settings. Recent upstream commits in this
area (`CCBC-1702`, `CCBC-1699`, `CCBC-1695`) are all rebalance/failover/TLS teardown fixes — treat
this code as historically fragile and read the surrounding commits before changing it.

## Authentication

`lcb::Authenticator` (`src/auth-priv.h`, `src/auth.cc`). Modes (`include/libcouchbase/auth.h:395`):

| Mode | Value | Meaning |
|---|---|---|
| `LCBAUTH_MODE_CLASSIC` | 0 | Pre-5.0 per-bucket passwords. `LCBAUTH_F_BUCKET` allowed. |
| `LCBAUTH_MODE_RBAC` | 1 | Role-based user/password. `LCBAUTH_F_CLUSTER` only. |
| `LCBAUTH_MODE_DYNAMIC` | 2 | Credentials resolved per-request via callback (`lcbauth_set_callback`). |
| `LCBAUTH_MODE_JWT` | 3 | **Fork-specific.** Bearer-token auth. |

The library asks for credentials via an `lcbauth_CREDENTIALS` object carrying an
`lcbauth_SERVICE` (KV / QUERY / SEARCH / ANALYTICS / MANAGEMENT / EVENTING / VIEWS) and an
`lcbauth_REASON` (`NEW_OPERATION`, `AUTHENTICATION_FAILURE`, `AUTHORIZATION_FAILURE`) — so a dynamic
provider can distinguish "first attempt" from "retry after rejection".

### JWT (the fork's reason for existing)

Public entry point: `lcbauth_set_jwt(auth, jwt, jwt_len)`.

Behaviour, all in `src/auth.cc`:

1. **Rejects mixing.** `set_jwt()` returns `LCB_ERR_OPTIONS_CONFLICT` if a username, password, or
   bucket credential is already set (`auth.cc:146`). Symmetrically, `lcbauth_add_pass()` returns
   `LCB_ERR_OPTIONS_CONFLICT` once the authenticator is in JWT mode (`auth.cc:183`).
2. **Parses at set-time, not use-time** (`parse_jwt`, `auth.cc:67`). Requires exactly 3 dot-separated
   segments; base64url-decodes all three; requires header and payload to be JSON objects. Reads `exp`
   if present and numeric. **The signature is decoded but not verified** — the server does that.
   Failures are `LCB_ERR_INVALID_ARGUMENT`.
3. **Precomputes and caches** three strings (`store_jwt`, `auth.cc:121`): the raw token, the HTTP
   header value `"Bearer <jwt>"`, and the SASL OAUTHBEARER initial response
   `"n,,\x01auth=Bearer <jwt>\x01\x01"` (RFC 7628). All are wiped with `secure_zero_string()` on
   overwrite/destruct; `mode_switch` away from JWT clears them.
4. **TLS is mandatory.** `lcb_create()` fails with `LCB_ERR_OPTIONS_CONFLICT` if the authenticator is
   in JWT mode and the connection string has no SSL (`src/instance.cc:486`). Caveat worth knowing:
   that check only inspects `options->auth`, so an authenticator attached later via `lcb_set_auth()`
   bypasses it.
5. **HTTP / analytics** (`src/http/http.cc:663,717-725`): emits `Authorization: Bearer <jwt>` instead
   of Basic; `credentials_for()` returns empty user/pass in JWT mode so no Basic header is built.
6. **KV** (`src/mcserver/negotiate.cc:238-324`): bypasses `cbsasl` entirely and uses `OAUTHBEARER`,
   a single-round-trip mechanism. `LCB_CNTL_FORCE_SASL_MECH` is **ignored** (logged as such). If the
   server does not advertise `OAUTHBEARER` the connection **hard-fails** — no silent downgrade to
   PLAIN/SCRAM. Requires Couchbase Server **8.1+**. An unexpected `SASL_CONTINUE` is also an error,
   since OAUTHBEARER is single-step.
7. Logs never contain the token — `Authenticator::describe()` emits `jwt(exp=…)` / `jwt(no-exp)`.

Reference implementation: `example/analytics-jwt/analytics_jwt_tls.cc` (TLS connect + `SELECT 1`).
Tests: `tests/basic/t_jwt_auth.cc`.

Contract note: the Power BI connector and ODBC driver pass `AuthMode=jwt` + `JWT=<token>` through the
ODBC connection string; the driver translates that into `lcbauth_set_jwt`. Changing the JWT API here
breaks that chain — see the parent repo's `CLAUDE.md` and `JWT_E2E_WINDOWS_CHECK.md`.

## The analytics path (what ODBC actually exercises)

1. `lcb_cmdanalytics_create()` → an `lcb_CMDANALYTICS` (`src/capi/cmd_analytics.hh`). Either build it
   piecewise (`_statement`, `_named_param`, `_positional_params`, `_readonly`, `_priority`,
   `_consistency`, `_scope_name`, `_timeout`, `_client_context_id`, `_deferred`, `_on_behalf_of`) or
   hand it a pre-encoded JSON body with `_payload` / `_encoded_payload`. **The ODBC driver uses
   `_payload`** — it builds the request JSON itself.
2. `lcb_cmdanalytics_callback()` installs the row callback. Analytics is *not* registerable via
   `lcb_install_callback()`; its callback type `LCB_CALLBACK_ANALYTICS` is a negative pseudo-type
   (`couchbase.h:517`), same as query/search/views.
3. `lcb_analytics()` (`src/analytics/analytics.cc:67`) copies the command into a `shared_ptr`,
   allocates an `lcb_ANALYTICS_HANDLE_`, and schedules it. Failures before scheduling are delivered
   through the callback with `is_final` set, not just as a return code — so **always** handle both.
4. `lcb_ANALYTICS_HANDLE_::issue_htreq()` (`analytics_handle.cc:252`) turns it into an
   `LCB_HTTP_TYPE_ANALYTICS` HTTP request: `POST /query/service`, `Content-Type: application/json`,
   **streaming enabled**. A deferred handle instead becomes a `GET` against the URL the server
   returned (host and path extracted from it). `cb-on-behalf-of` is added if set.
5. The response body is fed to `lcb::jsparse::Parser`; `JSPARSE_on_row` fires the user callback **once
   per row** with `lcb_respanalytics_row()` pointing at that row's JSON. Malformed JSON →
   `LCB_ERR_PROTOCOL_ERROR`.
6. One **final** callback (`lcb_respanalytics_is_final() != 0`) carries the terminal status, the
   metadata block, and the error context. Non-200 / non-`LCB_SUCCESS` becomes `LCB_ERR_HTTP`
   (`analytics_handle.hh:186`).
7. Errors: `lcb_respanalytics_error_context()` → `lcb_errctx_analytics_statement()`,
   `_first_error_code()`, `_first_error_message()`. **This is where the useful server-side diagnostic
   lives** — the `lcb_STATUS` alone is usually too coarse to report to a user.
8. `lcb_analytics_cancel(instance, handle)` cancels in flight; handles come from
   `lcb_cmdanalytics_handle()` (before) or `lcb_respanalytics_handle()` (from a callback).

Query (`src/n1ql/`), search (`src/search/`), and views (`src/views/`) follow the identical
command → handle → HTTP-streaming → jsparse → row-callbacks + final-callback shape. If you understand
analytics you understand all four.

## Error handling

`include/libcouchbase/error.h` defines every code in **one X-macro table** (`line 67+`) — code, numeric
value, type, flags, description. Read that table rather than searching for individual codes.

Types (`error.h:43`): `SUCCESS`, `BASE` (1xx), `SHARED` (2xx), `KEYVALUE` (3xx), `QUERY` (4xx),
`ANALYTICS` (5xx), `SEARCH` (6xx), `VIEW` (7xx), `MANAGEMENT` (8xx), `SDK` (10).

Flags + their predicate macros (`error.h:56`, `223`): `NETWORK` / `SUBDOC` / `TRANSIENT` / `FATAL` /
`INPUT` → `LCB_ERROR_IS_NETWORK(e)`, `LCB_ERROR_IS_TRANSIENT(e)`, `LCB_ERROR_IS_INPUT(e)`, etc.
**Classify with these macros, not by comparing against code lists** — that's what they're for, and
`TRANSIENT`/`NETWORK` are precisely the retry signal.

Codes worth recognising: `LCB_ERR_TIMEOUT` (201, network+transient), `LCB_ERR_REQUEST_CANCELED` (202),
`LCB_ERR_INVALID_ARGUMENT` (203), `LCB_ERR_AUTHENTICATION_FAILURE` (206),
`LCB_ERR_OPTIONS_CONFLICT` (1030, SDK type — the JWT misconfiguration code),
`LCB_ERR_COMPILATION_FAILED` (501,
analytics), `LCB_ERR_DATASET_NOT_FOUND` (503), `LCB_ERR_DATAVERSE_NOT_FOUND` (504).

Render with `lcb_strerror_short()` (code mnemonic) / `lcb_strerror_long()` (description). Per-service
error contexts carry the server's own message and should be preferred when present.

## Settings and `lcb_cntl`

Three ways to reach the same settings:

- `lcb_cntl(instance, LCB_CNTL_SET|GET, LCB_CNTL_<X>, &value)` — typed, `include/libcouchbase/cntl.h`.
- `lcb_cntl_string(instance, "name", "value")` — string names + converters, table in `src/cntl.cc`.
- `?name=value` in the connection string — routed to `lcb_cntl_string()` for anything the connspec
  parser doesn't claim.

Converters in that table tell you the accepted value syntax: `convert_timevalue` (accepts `2.5` seconds
or `2500us`-style suffixes), `convert_intbool` (`on`/`off`/`true`/`false`/`0`/`1`),
`convert_compression`, `convert_retrymode`, `convert_ipv6`, `convert_passthru`.

Timeouts that matter to the ODBC path: `operation_timeout` (alias `timeout`), `analytics_timeout`,
`http_timeout`, `config_total_timeout`, `config_node_timeout`. Per-request
`lcb_cmdanalytics_timeout()` overrides the instance-level analytics timeout.

Environment variables are documented in `doc/environment.h`: `LCB_LOGLEVEL`, `LCB_OPTIONS`,
`LCB_NO_HTTP`, `LCB_NO_CCCP`, `LCB_SSL_MODE`, `LCB_SSL_CACERT`, `LCB_IOPS_NAME`, `LCB_IOPS_SYMBOL`,
`LCB_DLOPEN_DEBUG`. `LCB_LOGLEVEL=5` + `LCB_OPTIONS` is the fastest way to debug a connection problem
without recompiling.

## I/O backends

Selected at runtime by `src/iofactory.c`, which `dlopen`s a plugin (or uses a built-in). Backends live
in `plugins/io/`: `libevent`, `libev`, `libuv`, `select`, `iocp`. `src/lcbio/` is written against the
abstract `lcb_io_opt_st` (`include/libcouchbase/iops.h`) so it works with both event-style
(libevent/libev) and completion-style (IOCP/libuv) loops — a real source of subtlety, and the reason
several recent fixes are libuv- or IOCP-specific (`CCBC-1695`, `CCBC-1694`).

You can also drive an external loop directly — see `example/libeventdirect` and `example/libuvdirect`.

## Build

```sh
git submodule update --init --recursive   # if applicable in the parent checkout
mkdir build && cd build
../cmake/configure          # Perl wrapper, autotools-like; or invoke cmake directly
make
ctest
```

Key options (`CMakeLists.txt:43-69`): `LCB_NO_TESTS`, `LCB_NO_TOOLS`, `LCB_NO_PLUGINS`, `LCB_NO_SSL`,
`LCB_BUILD_LIBEVENT/LIBEV/LIBUV`, `LCB_BUILD_EXAMPLES` (**OFF** by default — turn it on to build the
JWT example), `LCB_USE_HDR_HISTOGRAM` (**must be OFF for the Windows ODBC build**, per the parent
repo's build recipe), `LCB_USE_ASAN`, `LCB_DUMP_PACKETS`, `LCB_TLS_LOG_KEYS`, `LCB_NO_MOCK`,
`LCB_SKIP_GIT_VERSION`.

Dependencies: libevent (or libev), OpenSSL, CMake ≥ 3.17. Style is `.clang-format` at the repo root;
`tools/check-clang-format` and `tools/check-clang-static-analyzer` are the CI gates.

## Tests

GTest-based, built as separate binaries (`tests/CMakeLists.txt`), driven by `ctest`.

- `tests/basic/` → the `nonio-tests` binary. Pure-unit, **no server or mock needed**. This is where
  `t_jwt_auth.cc`, `t_connstr.cc`, `t_creds.cc`, `t_base64.cc`, `t_jsparse.cc`, `t_analytics.cc` live —
  put new pure-logic tests here.
- `tests/iotests/` → needs **CouchbaseMock** (`CouchbaseMock-1.5.25.jar`, downloaded by CMake;
  `tests/start_mock.sh`) or a real cluster. `t_confmon.cc`, `t_netfail.cc`, `t_n1ql.cc` etc.
- `tests/mc/`, `tests/rdb/`, `tests/vbucket/`, `tests/socktests/` → per-subsystem binaries.
- `tests/ioserver/` → a toy socket server used by the socket tests.
- `check-all` is the aggregate runner. `LCB_NO_MOCK=ON` skips everything mock-dependent.

Non-obvious: several tests are written to tolerate real-cluster flakiness (widened `OP_TIMEOUT`,
`TMPFAIL` bursts — see commits `60b60867`, `15cadde6`). Don't tighten those bounds without reading why
they were loosened.

## Conventions

- Public API: `lcb_*` / `lcbauth_*` / `lcbtrace_*` / `lcbmetrics_*`, C linkage, annotated with
  `LIBCOUCHBASE_API` and a stability tag (`@committed`, `@uncommitted`, `@volatile`, `@private` — see
  `doc/apiattr.h`). `LCB_UNCOMMITTED_API` marks newer additions.
- Internals are C++ in `lcb::` namespaces but exposed to the C API as opaque pointers; the concrete
  structs are `lcb_CMD*_`/`lcb_RESP*_`/`lcb_*_HANDLE_` (trailing underscore) in `src/capi/` and the
  per-service `*_handle.hh` files.
- Commands are heap-allocated, populated with setters, passed to the operation, then destroyed by the
  caller. The library copies what it needs — destroying the command right after scheduling is correct
  and is what the ODBC driver does.
- Logging goes through `lcb_log(LOGARGS(this, LEVEL), LOGFMT ..., LOGID(this), ...)`. Never log
  credentials or tokens; use a `describe()`-style redacted summary.
- Never add a per-file `#if APPLE / #if WIN32` for dependency resolution — platform splits belong in
  `CMakeLists.txt` / `cmake/Modules/`.

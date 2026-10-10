# nats-pure.rb vs. the NQ oracle inventory: missing features

This is a feature-gap audit of nats-pure.rb against the symbol inventory that
[NQ](https://github.com/wallyqs/nq.dev) uses as its oracle contract. It lists
what nats-pure.rb would still need for parity with an NQ client.

The audit pins these inputs:

| Input | Revision |
| --- | --- |
| nats-pure.rb | `1b4cf34` (upstream `nats-io/nats-pure.rb` `main`, v2.7.0+) |
| nq.dev | `e602352` (`ir/contract.json`, `ir/jetstream-contract.json`, `ir/services-contract.json`, `ir/orbit-contract.json`) |
| Oracle: nats.go, nats.go/jetstream, nats.go/micro | `7a8404ab9b1721cf1eddf3a26474e6925c322d73` |
| Oracle: orbit.go/jetstreamext | `8898afea0bc0f1a22fa00ff67414a71f590886a2` |

## Method

Every one of the 1,410 oracle symbols in NQ's four contract files was checked
against nats-pure.rb's public API by reading its source. The checks used
`lib/`, `sig/`, the README, `docs/` and `spec/` as evidence, and NQ's Ruby
binding showed what each symbol means in Ruby. Each symbol got one of these
statuses:

- **present**: a public equivalent exists. Names and shapes may differ, for
  example snake_case keywords, Struct members, or raw server strings for enums.
- **partial**: the feature exists, but it is incomplete or behaves
  differently. The note in the inventory says how.
- **missing**: there is no public equivalent.
- **n/a**: a Go-only idiom such as a functional-option type, a
  `context.Context` variant, or a channel. NQ's Ruby client does not expose
  these either.

The per-symbol results are in [`inventory.tsv`](inventory.tsv). Its columns
are the area, the oracle symbol, the Go signature and source line, NQ Ruby's
status and binding, and nats-pure's status, location and a note.

The **NQ Ruby status** column is NQ's own claim, taken from its contract
files. `implemented` there means NQ binds the symbol and has named tests that
measure it against the oracle. `planned` means NQ does not have it yet
either.

## Summary

| Area | Oracle symbols | Present | Partial | Missing | n/a | Missing or partial in nats-pure but implemented in NQ Ruby |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Core NATS (`nats.go`) | 282 | 101 | 52 | 95 | 34 | 146 |
| JetStream operations | 250 | 101 | 36 | 86 | 27 | 108 |
| JetStream data types | 415 | 305 | 38 | 72 | 0 | 17 |
| Key-Value and Object Store | 239 | 71 | 22 | 138 | 8 | 109 |
| Services (`micro`) | 121 | 82 | 14 | 15 | 10 | 29 |
| Batch and fast-ingest publishing (orbit.go) | 103 | 9 | 25 | 62 | 7 | 60 |
| **Total** | **1410** | **669** | **187** | **468** | **86** | **469** |

The last column is the concrete gap to an NQ client: 469 symbols that NQ's
Ruby client binds and tests, but that nats-pure.rb lacks or only partly
supports. The other gaps are oracle features that NQ also has only as
`planned`.

## Missing features that the NQ Ruby client implements

### Core NATS

- **Connection introspection.** These are missing: `connected_addr`,
  `local_addr`, a redacted connected URL, TLS connection state,
  `num_subscriptions`, `buffered`, `rtt`, `new_resp_inbox`, `barrier`,
  `set_server_pool`, and getters for the current handlers. The `on_*` methods
  only set handlers.
- **Server INFO accessors.** These are partial: there are no typed accessors
  for `auth_required`, `client_id`, `client_ip`, the connected server's
  id/name/version/cluster, `jetstream`, `headers`, `max_payload`,
  `tls_required` or the system account. The only route is the raw
  `nc.server_info[:key]` hash.
- **Callbacks.** These are missing: connected, discovered servers, lame-duck
  mode, `ReconnectToServer`, custom reconnect delay, and no callbacks after
  close. Reconnect errors are partial, because they only reach the generic
  `on_error`.
- **Reconnect tuning.** Reconnect jitter (plain and TLS), the reconnect buffer
  size and `IgnoreAuthErrorAbort` are missing. `RetryOnFailedConnect` is
  partial: the first connect retries the pool while blocking, and there is
  no asynchronous mode. Reconnecting on a flusher error is always on, so it
  is partial.
- **Connection and transport options.** These are missing: `no_echo` (CONNECT
  never sends `echo`), a custom dialer, `skip_host_lookup`, TLS handshake
  first, write buffer size, and flusher timeout. `connect_timeout` is partial:
  it only covers the INFO/PONG reads, and the TCP dial always uses
  `DEFAULT_CONNECT_TIMEOUT` (`lib/nats/io/client.rb:1810`).
- **TLS options.** These are partial: `client_cert`, `root_cas`, the
  client TLS config, and the TLS certificate and root-CA callbacks have no
  dedicated options. They work only through a user-built `SSLContext` passed
  as `tls: {context:}`.
- **Authentication.** A token handler, a user-info handler and user
  credentials from bytes are missing. JWT plus seed is partial: it only works
  by hand-writing `user_jwt_cb` and `user_signature_cb`.
- **WebSocket.** Compression, connection headers and the headers handler are
  missing. The proxy path is partial: it can only be set in the `ws://` URL.
- **Subscription API.** These are missing: a public `Subscription#drain`
  (only the private `drain_sub` exists), `draining?`, `dropped`,
  `max_pending`, `clear_max_pending`, and a per-subscription closed handler.
  These are partial: `valid?`, `pending` and queued messages are reachable
  only through raw accessors. Pending limits take effect only at subscribe
  time; writing the accessor later does not resize the `SizedQueue`.
- **Messages.** `Msg#==` and `Msg#size` are missing. `respond_msg` is
  partial: it does not set the subject to the reply. `new_inbox` is partial
  because it exists only as an instance method.
- **Validation.** There are no checks on queue names, timeouts, max payload,
  header support, mixed `ws`/`nats` schemes or conflicting auth options.
  Subject validation only rejects empty subjects.
- **Error taxonomy.** About 25 specific errors are missing, among them
  `BadHeaderMsg`, `MaxPayload`, `MaxMessages`, `SyncSubRequired`,
  `MsgNotBound`, `Disconnected`, `ConnectionReconnecting`,
  `ReconnectBufExceeded`, `TLS`, `HeadersNotSupported`, `NoEchoNotSupported`
  and the auth-configuration errors. These are partial: auth expired or
  revoked, permission violations, max connections and subscriptions, no INFO
  and secure-connection errors all surface as a generic `AuthError`,
  `ServerError` or `ConnectError` that carries the server's text.

### JetStream

- **Asynchronous publish.** This is missing entirely: `publish_async`, the
  ack futures (`ok`, `err`, `msg`), `publish_async_pending` and
  `publish_async_complete`, cleanup, the async options such as stall wait and
  max pending, and the related errors.
- **Publish retry.** Retry attempts and retry wait are missing. With no
  responders, `js.publish` raises `NoStreamResponse` immediately.
- **The new `jetstream`-package consume API.** These are missing:
  `Consumer#consume` and `Consumer#messages` (the `ConsumeContext` and
  `MessagesContext` objects, with `stop`, `drain` and `closed`); the
  max-messages, max-bytes, threshold, heartbeat, `StopAfter` and
  error-handler options; and errors such as consumer already consuming,
  iterator closed and no heartbeat. nats-pure follows the legacy
  `JetStreamContext` API (`js.subscribe`, `pull_subscribe`, `fetch`).
- **Fetch gaps.** Fetch by bytes (and so the max-bytes-exceeded error) and
  fetch with heartbeat are missing. Cancellation is partial: there is only a
  timeout. An error that arrives after some messages is dropped silently. An
  empty fetch raises `NATS::Timeout` instead of a no-messages error.
- **Ordered consumers.** These are missing at both the stream and the context
  level, along with `OrderedConsumerConfig` and its errors. Only the KV
  watcher uses an ordered consumer, internally.
- **Push consumers.** These are partial: a callback `js.subscribe` acks
  automatically by default, does not monitor heartbeats and does not answer
  flow-control requests.
- **Stream and consumer handles.** There are no `Stream`, `Consumer` or
  `PushConsumer` objects with cached info. Operations are context-level and
  take the stream name. `create_or_update_stream` is partial: it takes two
  calls.
- **Listing.** `list_streams`, `stream_names`, `list_consumers` and
  `consumer_names` are missing. Only `find_stream_name_by_subject` exists.
- **Stream data operations.** Stream purge (with subject, sequence or keep),
  `delete_msg` and `secure_delete_msg` are missing.
- **Typed JetStream errors.** About 20 server error codes are not mapped to
  classes and arrive as generic `BadRequest`, `ServerError` or `NotFound`
  with an `err_code`. Examples are consumer create, name already in use,
  duplicate, overlapping and empty filters, max consumers, stream name in
  use, message not found, JetStream not enabled, the message-schedule errors,
  and the 409 pull statuses for consumer deleted, leadership changed and
  server shutdown. These client errors are missing: not a pull consumer, not
  a push consumer, message has no reply, message not bound, invalid
  JetStream response, and invalid subject.
- **Checks that the server applied a setting.** The client never checks that
  the server applied stream sources, subject transforms, multiple filter
  subjects or the limit marker TTL, and has none of the matching
  not-supported errors.
- **Data-type fidelity.** These are partial:
  - `ack_wait`, `idle_heartbeat`, `inactive_threshold`,
    `priority_timeout` and `pause_remaining` accept and decode whole seconds
    only, while `backoff` and `max_expires` stay in raw nanoseconds.
  - Time fields stay as strings. `opt_start_time` given as a Ruby `Time`
    serializes with `to_s`, which is not RFC 3339.
  - `StreamState` drops `deleted`, `num_deleted`, `num_subjects` and
    `subjects`.
  - The raw stream message drops `time`. Its sequence is a String on the
    direct-get path, and repeated header keys collapse into one.

### Key-Value

- **Bucket management.** `update_key_value`, `create_or_update_key_value`,
  `key_value_store_names` and `key_value_stores` are missing.
- **Per-key TTL and limit markers.** The key TTL and purge TTL options and the
  `limit_marker_ttl` config and status are missing. `JetStream#publish(ttl:)`
  exists, but the KV API does not use it.
- **`purge_deletes`, including delete markers older than a threshold.** This
  is missing, because there is no stream purge API to build it on.
- **Watch options.** `resume_from_revision` and `updates_only` are missing.
- **Entries.** `get` returns an entry without `created` or `operation`. The
  operation is a raw header string, `nil` for a put, and there is no
  operation enum.
- **Listing.** `keys` raises on an empty bucket and has no early stop, so
  breaking out of it leaks the watcher. It also ignores filters, so filtered
  key listing is partial.
- **Handles and status.** `bucket` and `backing_store` are missing. `bytes`
  and `config` are reachable only through the raw stream info.
- **Errors.** Bucket exists, bucket malformed, bucket required, invalid bucket
  name and config required are missing; `VALID_BUCKET_RE` is defined but
  never used. Key exists raises `KeyWrongLastSequenceError` instead. The
  invalid-key error is raised only with the opt-in `validate_keys`.
- **Placement.** This is silently dropped: it is a Struct member, but
  `create_key_value` never passes it to the stream config.

### Object Store

nats-pure.rb has no Object Store. Everything is missing: the manager (create,
update, delete, list, names), put, get, info, delete, links, meta updates,
watch and list, status, the digest helpers and every object error. NQ's Ruby
client implements the methods, statuses, errors and digest helpers. NQ also
has some config, info and meta fields only as `planned`.

### Services (`micro`)

- **Error handling.** There is no error handler and no `NATSError`. A
  `NATS::Error` raised in a handler, or a failed subscribe, stops the service.
  A closed connection does not stop the service, although in Go it does.
- **Control subjects.** There is no public `control_subject(verb, name, id)`,
  and the service-name-required and verb-not-supported errors are missing.
- **Endpoints.** A default endpoint at creation and endpoint pending limits
  are missing. Turning off the queue group has no flag; `queue: ""` happens to
  work but is undocumented.
- **Responses.** `respond_json`, the marshal-response error and response
  headers are missing. `Request#respond` echoes the request headers and the
  requester's reply-to, through `Msg#respond`.
- **Error constants and arguments.** The error header names are string
  literals, not constants. `respond_with_error` accepts an empty code or
  description. The respond error is not wrapped.
- **Info and stats.** `service.info` and `service.stats` lack `:type`, and
  there is no public ping object. `reset` does not reset the started time.
- **Validation.** The name regex has no `^` anchor, and a missing name or
  version is not rejected.

### Batch and fast-ingest publishing (orbit.go `jetstreamext`)

- **Atomic batch publishing.** nats-pure has only the batch header constants
  and the `batch` and `count` fields on `PubAck`. These are missing:
  `BatchPublisher`, `new_batch_publisher`, `publish_msg_batch`, `add`,
  `discard`, `size`, `closed?`, the per-message `WithBatchExpect*` and TTL
  options, `BatchAck`, and the end-of-batch commit constant.
- **Fast-ingest publishing.** This is missing entirely: the publisher,
  `FastPubAck`, flow control, the options and the gap-detected error.
- **Errors.** The 15 server batch errors arrive without named classes. The
  matching `JSErrCode*` constants and the client batch errors are missing:
  batch closed, empty batch, invalid batch ack and invalid option.
  `err_code` 10204 with status 400 maps to `ConsumerInvalidReset` in
  `JS.from_error`. NQ also uses 10204 for the fast-batch invalid pattern, so
  that error may be misreported. Confirm this against a server.

## Oracle features that NQ Ruby also lacks

NQ marks these 146 missing and 39 partial symbols as `planned`, so they are
not yet a gap to an NQ client:

- the `ConsumeContext`, `MessagesContext` and `OrderedConsumerConfig`
  *types*, and the lister types;
- stream-info options (`deleted_details`, `subjects_filter`);
- stream list by subject;
- stream purge options;
- client tracing;
- KV mirror and sources buckets;
- Object Store config, info and meta types;
- batch flow control;
- batch direct get (`GetBatch`, `GetLastMsgsFor`).

## What nats-pure.rb has beyond the oracle and NQ

- Fork detection with reconnect after fork, Ractor support and a Rails
  reloader hook.
- Per-subscription `processing_concurrency` on a shared executor, and
  `pending_bytes_limit` at subscribe time.
- A block-form async request, `NATS_*` environment-variable overrides,
  `close_timeout`, and `connecting?` and `disconnected?`.
- Legacy `js.subscribe` with automatic consumer creation, and
  `pull_subscribe` that looks up the stream by subject.
- `fetch` with a block, pinned-client tracking, direct `get_msg`, ack
  requests with `ack(timeout:)`, and a validating `publish(schedule:)`
  builder.
- KV: opt-in `validate_keys`, the `direct` bucket option, watch heartbeat
  and inactivity options with consumer re-creation, and an Enumerable
  watcher.
- Services: handler exceptions are answered as 500s and counted,
  `respond_with_error` accepts an Exception, String or Hash, `on_stop`
  receives the error, and endpoints and groups can be listed.

## Behavior differences found during the audit

These turned up while checking symbols. Each needs a test before it is
treated as a bug:

- `next_msg` on an async (callback) subscription raises `NoMethodError`.
- Repeated header keys overwrite each other; there are no multi-value
  headers.
- `connected?` is false while draining; nats.go's `IsConnected` is true.
- A permission violation becomes `AuthError` when the server requires auth.
- Writing a subscription's pending limits after subscribe does not resize its
  queue and can block the reader.

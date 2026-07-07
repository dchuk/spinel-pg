# pg (spinel-pg)

A pure spinel-Ruby PostgreSQL client — protocol v3, simple query, text
results — over spinel's `sp_net` sockets. Sibling of
[spinel-redis](https://github.com/rubys/spinel-redis), same
architecture end to end: pure wire functions, a `try_next`/ivar
incremental parser, a client core over an injected transport duck
(dual-runtime testable), and a thin `sp_net` transport.

```ruby
require "pg"

conn = PG.connect("127.0.0.1", 5432, "mastodon", "app", "secret")
r = conn.exec("SELECT id, name FROM accounts ORDER BY id")
r.ntuples          # => 2
r.fields           # => ["id", "name"]
r.getvalue(0, 1)   # => "alice"    (nil for NULL)
r.cmd_tag          # => "SELECT 2"
```

## Auth: trust, cleartext, SCRAM-SHA-256

SCRAM rides pure-Ruby SHA-256 / HMAC / PBKDF2 (`pg/scram.rb`) rather
than `sp_crypto`: every sp_crypto entry point is `const char *` with
strlen semantics, and SCRAM's intermediate keys are raw 32-byte digests
that routinely contain NULs — they'd silently truncate
(matz/spinel#1779 asks for explicit-length variants). Compiled by
spinel the pure version is native-code speed, and auth runs once per
connection, so PBKDF2's 4096 iterations don't matter. The crypto is
pinned to published vectors (FIPS 180-4, RFC 4231, the full RFC 7677
SCRAM exchange) in the dual-runtime parity lane, and the live lane
authenticates against a real PostgreSQL 17 with `--auth=scram-sha-256`
— including rejecting a wrong password.

MD5 auth is deliberately not implemented (ledgered; servers have
defaulted to SCRAM since PG 14).

## Tests

```sh
spin test    # scram + client lanes also run under CRuby and must match
```

The live lanes (`live_test`, `live_scram_test`) initdb throwaway
instances on private ports and tear them down; they need
`initdb`/`pg_ctl`/`postgres` on PATH (brew:
`/opt/homebrew/opt/postgresql@17/bin`). Snapshots committed.

The pg-gem oracle lane (replaying flows through the real `pg` gem, as
spinel-redis does with redis-rb) lights up once the gem is installed:
`gem install pg -- --with-pg-config=/opt/homebrew/opt/libpq/bin/pg_config`.

## v0.1 exclusion ledger

- **Extended query protocol** (parse/bind/execute, parameters) — simple
  query only; interpolation safety is the caller's problem until then.
  This is the first thing the ActiveRecord seam will force.
- **MD5 auth**, **TLS/sslmode** (sp_net TLS = matz/spinel#1054),
  **COPY**, **LISTEN/NOTIFY**, **portals/cursors**, **binary format
  results**, **connection pooling**, **unix sockets**.
- Multi-statement `exec` strings: last result wins.
- `PG.connect` is positional; the gem's kwargs/URL forms come with the
  seam work.

## Spinel notes

- matz/spinel#1778 — `String#include?` truncates at NUL bytes; tests
  use a byte-exact scan for wire assertions.
- matz/spinel#1779 — sp_crypto explicit-length variants (found here).
- The workaround idioms from spinel-redis carry over (`.to_s` at wire
  boundaries; assign-then-return; sequential statements). #1773/#1775
  themselves were fixed upstream same-day (spinel a7e42e90) — the
  shapes are kept for compatibility with pre-fix builds.

# pg — a pure spinel-Ruby PostgreSQL client (protocol v3, simple and
# extended query) over sp_net sockets. Auth: trust, cleartext password,
# SCRAM-SHA-256 (pure-Ruby SHA-256/HMAC/PBKDF2 — sp_crypto's
# strlen-based params can't carry SCRAM's raw binary keys).
#
#   conn = PG.connect("127.0.0.1", 5432, "mastodon", "app", "secret")
#   r = conn.exec("SELECT id, name FROM users")
#   r.ntuples, r.fields, r.getvalue(0, 1)   # nil for NULL
#   r = conn.exec_params("SELECT name FROM users WHERE id = $1", ["7"])
require "pg/wire"
require "pg/scram"
require "pg/client"
require "pg/sock"
require "pg/connection"

module PG
  def self.connect(host, port, database, user, password)
    t = PgTransport.new(host, port)
    nonce = PgRand.sp_crypto_random_b64url(18)
    c = PgClientCore.new(t, user, database, password, nonce)
    c.connect!
    c
  end
end

# Client-core conformance against a scripted backend — dual-runtime.
# Backend bytes are built with the same pure wire helpers the encoder
# side is tested with; auth flows cover trust, cleartext, and the full
# RFC 7677 SCRAM exchange (fixed nonce makes it deterministic).
require "pg/wire"
require "pg/scram"
require "pg/client"

class ScriptedTransport
  def initialize(chunks)
    @chunks = chunks
    @i = 0
    @written = ""
  end

  def write(data)
    @written = @written + data
    data.bytesize
  end

  def read_some(max)
    if @i >= @chunks.length
      return ""
    end
    c = @chunks[@i]
    @i = @i + 1
    c
  end

  def close
    0
  end

  def written
    @written
  end
end

# Byte-exact substring scan: spinel's String#include? truncates at NUL
# bytes (matz/spinel#1778), and PG wire bytes are NUL-riddled.
def wire_has(haystack, needle)
  hn = haystack.bytesize
  nn = needle.bytesize
  if nn == 0
    return true
  end
  i = 0
  while i + nn <= hn
    j = 0
    while j < nn
      if haystack.getbyte(i + j) != needle.getbyte(j)
        break
      end
      j = j + 1
    end
    if j == nn
      return true
    end
    i = i + 1
  end
  false
end

def bmsg(kind, body)
  kind + PgWire.be32(body.bytesize + 4) + body
end

def auth_ok
  bmsg("R", PgWire.be32(0))
end

def ready_idle
  bmsg("Z", "I")
end

Z = [0].pack("C*")

# --- trust auth: R(0) -> S -> K -> Z ----------------------------------------

script = [
  auth_ok +
  bmsg("S", "server_version" + Z + "17.0" + Z) +
  bmsg("K", PgWire.be32(1234) + PgWire.be32(5678)) +
  ready_idle
]
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "app", "appdb", "", "nonce")
c.connect!
puts "trust_ready  " + c.ready?.to_s
w = t.written
ok = w.getbyte(4) == 0 && w.getbyte(5) == 3   # protocol 3.0
ok = ok && wire_has(w, "user" + Z + "app" + Z)
ok = ok && wire_has(w, "database" + Z + "appdb" + Z)
puts "startup_wire " + ok.to_s

# --- cleartext password -------------------------------------------------------

script = [
  bmsg("R", PgWire.be32(3)),
  auth_ok + ready_idle
]
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "app", "appdb", "sekrit", "nonce")
c.connect!
puts "clear_ready  " + c.ready?.to_s
puts "clear_wire   " + wire_has(t.written, "p" + PgWire.be32(4 + 7) + "sekrit" + Z).to_s

# --- SCRAM-SHA-256 (RFC 7677 exchange verbatim as the server) -----------------

server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
# The RFC 7677 v= belongs to the n=user AuthMessage; PgClientCore sends
# n=, (the postgres form), so derive the matching ServerSignature with
# the same (vector-pinned) pure crypto.
salted = PgSha256.pbkdf2("pencil", PgBase64.decode("W22ZaJ0SNY7soEsUEjb6gQ=="), 4096)
server_key = PgSha256.hmac(salted, "Server Key")
snonce = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
auth_message = "n=,r=rOprNGfwEbeRWgbNEkqO" + "," + server_first + "," + "c=biws,r=" + snonce
server_final = "v=" + PgBase64.encode(PgSha256.hmac(server_key, auth_message))
script = [
  bmsg("R", PgWire.be32(10) + "SCRAM-SHA-256" + Z + Z),
  bmsg("R", PgWire.be32(11) + server_first),
  bmsg("R", PgWire.be32(12) + server_final) + auth_ok + ready_idle
]
t = ScriptedTransport.new(script)
# RFC vector carries n=user; PgClientCore sends n=, (postgres form), so
# drive PgScram-compatible expectations through the client by using the
# "user"-flavored vector pieces only for wire assertions we compute here.
c = PgClientCore.new(t, "user", "db", "pencil", "rOprNGfwEbeRWgbNEkqO")
c.connect!
puts "scram_ready  " + c.ready?.to_s
w = t.written
sc = PgScram.new("", "pencil", "rOprNGfwEbeRWgbNEkqO")
first = sc.client_first
final = sc.client_final(server_first)
ok = wire_has(w, "SCRAM-SHA-256" + Z + PgWire.be32(first.bytesize) + first)
ok = ok && wire_has(w, final)
puts "scram_wire   " + ok.to_s

# --- unsupported auth ---------------------------------------------------------

script = [bmsg("R", PgWire.be32(5) + "salt")]
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "u", "d", "p", "n")
raised = false
begin
  c.connect!
rescue => e
  raised = e.message.include?("md5")
end
puts "md5_raises   " + raised.to_s

# --- auth error from server ---------------------------------------------------

efields = "S" + "FATAL" + Z + "C" + "28P01" + Z + "M" + "password authentication failed" + Z + Z
script = [bmsg("E", efields)]
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "u", "d", "wrong", "n")
raised = false
begin
  c.connect!
rescue => e
  raised = e.message.include?("FATAL") && e.message.include?("authentication failed")
end
puts "auth_err     " + raised.to_s

# --- exec: two rows with a NULL, chunk-dribbled -------------------------------

def rowdesc(names)
  body = PgWire.be16(names.length)
  names.each do |nm|
    body = body + nm + [0].pack("C*") + PgWire.be32(0) + PgWire.be16(0) + PgWire.be32(25) + PgWire.be16(65535) + PgWire.be32(0) + PgWire.be16(0)
  end
  bmsg("T", body)
end

def datarow(vals, nullmask)
  body = PgWire.be16(vals.length)
  i = 0
  while i < vals.length
    if nullmask[i] == 1
      body = body + PgWire.be32(-1)
    else
      body = body + PgWire.be32(vals[i].bytesize) + vals[i]
    end
    i = i + 1
  end
  bmsg("D", body)
end

whole = rowdesc(["id", "name"]) +
        datarow(["1", "alice"], [0, 0]) +
        datarow(["2", ""], [0, 1]) +
        bmsg("C", "SELECT 2" + Z) +
        ready_idle
chunks = []
i = 0
while i < whole.bytesize
  chunks.push(whole.byteslice(i, 7))
  i = i + 7
end
script = [auth_ok + ready_idle]
chunks.each do |ch|
  script.push(ch)
end
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "u", "d", "", "n")
c.connect!
r = c.exec("SELECT id, name FROM t")
puts "exec_wire    " + wire_has(t.written, "Q" + PgWire.be32(27) + "SELECT id, name FROM t" + Z).to_s
puts "exec_shape   " + (r.ntuples == 2 && r.nfields == 2 && r.fields[0] == "id" && r.fields[1] == "name").to_s
puts "exec_tag     " + (r.cmd_tag == "SELECT 2").to_s
v = r.getvalue(0, 1)
puts "exec_value   " + (v == "alice").to_s
n = r.getvalue(1, 1)
puts "exec_null    " + n.nil?.to_s
puts "exec_nonnull " + (r.getvalue(1, 0) == "2").to_s
oob = r.getvalue(9, 9)
puts "exec_oob     " + oob.nil?.to_s

# --- exec error: E then Z raises after drain ----------------------------------

script = [
  auth_ok + ready_idle,
  bmsg("E", "S" + "ERROR" + Z + "M" + "relation \"nope\" does not exist" + Z + Z) + ready_idle
]
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "u", "d", "", "n")
c.connect!
raised = false
begin
  c.exec("SELECT * FROM nope")
rescue => e
  raised = e.message.include?("does not exist")
end
puts "exec_err     " + raised.to_s

# --- empty result set ----------------------------------------------------------

script = [
  auth_ok + ready_idle,
  rowdesc(["x"]) + bmsg("C", "SELECT 0" + Z) + ready_idle
]
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "u", "d", "", "n")
c.connect!
r = c.exec("SELECT x FROM t WHERE false")
puts "exec_empty   " + (r.ntuples == 0 && r.nfields == 1).to_s

# --- extended query ------------------------------------------------------------

# What the client wrote from byte `from` on, for byte-exact comparison
# (String#== also compares encodings once text is non-ASCII).
def sent_since(t, from)
  w = t.written
  w.byteslice(from, w.bytesize - from).b
end

def ready(status)
  bmsg("Z", status)
end

def err(state, msg)
  bmsg("E", "S" + "ERROR" + Z + "C" + state + Z + "M" + msg + Z + Z)
end

# exec_params: Parse/Bind/Describe/Execute/Sync in one write, NULL param
script = [
  auth_ok + ready_idle,
  bmsg("1", "") + bmsg("2", "") + rowdesc(["n", "s"]) +
  datarow(["7", ""], [0, 1]) + bmsg("C", "SELECT 1" + Z) + ready_idle
]
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "u", "d", "", "n")
st0 = c.transaction_status
c.connect!
puts "xq_status    " + (st0 == PG::PQTRANS_UNKNOWN && c.transaction_status == PG::PQTRANS_IDLE).to_s
from = t.written.bytesize
r = c.exec_params("SELECT $1::int AS n, $2 AS s", ["7", nil])
want = PgWire.parse("", "SELECT $1::int AS n, $2 AS s") + PgWire.bind("", "", ["7", nil]) +
       PgWire.describe("P", "") + PgWire.execute("", 0) + PgWire.sync
puts "xq_wire      " + (sent_since(t, from) == want.b).to_s
puts "xq_shape     " + (r.ntuples == 1 && r.nfields == 2 && r.fields[0] == "n" && r.fields[1] == "s").to_s
v = r.getvalue(0, 0)
n = r.getvalue(0, 1)
puts "xq_values    " + (v == "7" && n.nil?).to_s
puts "xq_tag       " + (r.cmd_tag == "SELECT 1").to_s

# prepare once, exec_prepared twice (no Parse), then close
script = [
  auth_ok + ready_idle,
  bmsg("1", "") + ready_idle,
  bmsg("2", "") + rowdesc(["v"]) + datarow(["a!"], [0]) + bmsg("C", "SELECT 1" + Z) + ready_idle,
  bmsg("2", "") + rowdesc(["v"]) + datarow(["!"], [0]) + bmsg("C", "SELECT 1" + Z) + ready_idle,
  bmsg("3", "") + ready_idle
]
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "u", "d", "", "n")
c.connect!
from = t.written.bytesize
r = c.prepare("s1", "SELECT $1::text || '!' AS v")
puts "prep_wire    " + (sent_since(t, from) == (PgWire.parse("s1", "SELECT $1::text || '!' AS v") + PgWire.sync).b).to_s
puts "prep_result  " + (r.ntuples == 0 && r.nfields == 0).to_s
run = PgWire.describe("P", "") + PgWire.execute("", 0) + PgWire.sync
from = t.written.bytesize
r1 = c.exec_prepared("s1", ["a"])
ok = sent_since(t, from) == (PgWire.bind("", "s1", ["a"]) + run).b
from = t.written.bytesize
r2 = c.exec_prepared("s1", [""])
ok = ok && sent_since(t, from) == (PgWire.bind("", "s1", [""]) + run).b
puts "prep_reuse   " + ok.to_s
puts "prep_values  " + (r1.getvalue(0, 0) == "a!" && r2.getvalue(0, 0) == "!").to_s
from = t.written.bytesize
c.close_prepared("s1")
puts "prep_close   " + (sent_since(t, from) == (PgWire.close("S", "s1") + PgWire.sync).b).to_s
c.close
puts "closed_state " + (c.transaction_status == PG::PQTRANS_UNKNOWN).to_s

# an Integer goes as its to_s, nil as NULL, through both entry points
script = [
  auth_ok + ready_idle,
  bmsg("1", "") + bmsg("2", "") + bmsg("n", "") + bmsg("C", "INSERT 0 1" + Z) + ready_idle,
  bmsg("2", "") + bmsg("n", "") + bmsg("C", "INSERT 0 1" + Z) + ready_idle
]
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "u", "d", "", "n")
c.connect!
from = t.written.bytesize
c.exec_params("INSERT INTO t VALUES ($1, $2, $3)", [42, nil, "x"])
ok = sent_since(t, from) == (PgWire.parse("", "INSERT INTO t VALUES ($1, $2, $3)") +
                             PgWire.bind("", "", ["42", nil, "x"]) + run).b
from = t.written.bytesize
c.exec_prepared("ins", [nil, 7])
ok = ok && sent_since(t, from) == (PgWire.bind("", "ins", [nil, "7"]) + run).b
puts "xq_mixed     " + ok.to_s

# a Parse error, then a Bind error whose ReadyForQuery arrives in a
# later read, then a good call dribbled in 3-byte chunks: each error
# raises only after ReadyForQuery, and the connection carries on
good = bmsg("1", "") + bmsg("2", "") + rowdesc(["x"]) + datarow(["1"], [0]) +
       bmsg("C", "SELECT 1" + Z) + ready_idle
script = [
  auth_ok + ready_idle,
  err("42601", "syntax error at or near \"SELEC\"") + ready_idle,
  err("26000", "prepared statement \"nope\" does not exist"),
  ready_idle
]
i = 0
while i < good.bytesize
  script.push(good.byteslice(i, 3))
  i = i + 3
end
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "u", "d", "", "n")
c.connect!
raised = false
begin
  c.exec_params("SELEC 1", [])
rescue => e
  raised = e.message.include?("syntax error")
end
puts "xq_err_parse " + raised.to_s
raised = false
begin
  c.exec_prepared("nope", [])
rescue => e
  raised = e.message.include?("does not exist")
end
puts "xq_err_bind  " + raised.to_s
r = c.exec_params("SELECT 1 AS x", [])
puts "xq_recovers  " + (r.getvalue(0, 0) == "1" && c.transaction_status == PG::PQTRANS_IDLE).to_s

# FATAL ends the session with no ReadyForQuery: raise its message at
# once. A connection lost while draining an error raises too. Either
# way the status is unknown.
script = [
  auth_ok + ready_idle,
  bmsg("E", "S" + "FATAL" + Z + "V" + "FATAL" + Z + "C" + "57P01" + Z +
            "M" + "terminating connection due to administrator command" + Z + Z)
]
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "u", "d", "", "n")
c.connect!
raised = false
begin
  c.exec_params("SELECT pg_sleep($1)", ["60"])
rescue => e
  raised = e.message.include?("terminating connection")
end
puts "xq_fatal     " + (raised && c.transaction_status == PG::PQTRANS_UNKNOWN).to_s
# the untranslated "V" decides (an Italian server says FATALE in "S");
# without "V" (servers before 9.6), "S" does
script = [
  auth_ok + ready_idle,
  bmsg("E", "S" + "FATALE" + Z + "V" + "FATAL" + Z + "C" + "57P01" + Z + "M" + "terminazione della connessione" + Z + Z)
]
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "u", "d", "", "n")
c.connect!
ok = false
begin
  c.exec_params("SELECT 1", [])
rescue => e
  ok = e.message.include?("terminazione") && c.transaction_status == PG::PQTRANS_UNKNOWN
end
script = [auth_ok + ready_idle, bmsg("E", "S" + "PANIC" + Z + "C" + "XX000" + Z + "M" + "out of shared memory" + Z + Z)]
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "u", "d", "", "n")
c.connect!
begin
  c.exec_params("SELECT 1", [])
rescue => e
  ok = ok && e.message.include?("out of shared memory") && c.transaction_status == PG::PQTRANS_UNKNOWN
end
puts "xq_fatal_sev " + ok.to_s
script = [auth_ok + ready("T"), err("42601", "syntax error")]
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "u", "d", "", "n")
c.connect!
raised = false
begin
  c.exec_params("SELEC 1", [])
rescue => e
  raised = e.message.include?("connection lost")
end
puts "xq_lost      " + (raised && c.transaction_status == PG::PQTRANS_UNKNOWN).to_s

# transaction status: BEGIN, an error inside it, a call refused in the
# failed transaction, ROLLBACK
script = [
  auth_ok + ready_idle,
  bmsg("C", "BEGIN" + Z) + ready("T"),
  bmsg("1", "") + bmsg("2", "") + bmsg("n", "") +
  err("23505", "duplicate key value violates unique constraint \"t_v_key\"") + ready("E"),
  err("25P02", "current transaction is aborted, commands ignored until end of transaction block") + ready("E"),
  bmsg("C", "ROLLBACK" + Z) + ready_idle
]
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "u", "d", "", "n")
c.connect!
c.exec("BEGIN")
puts "tx_intrans   " + (c.transaction_status == PG::PQTRANS_INTRANS).to_s
raised = false
begin
  c.exec_params("INSERT INTO t (v) VALUES ($1)", ["dup"])
rescue => e
  raised = e.message.include?("duplicate key")
end
puts "tx_err       " + (raised && c.transaction_status == PG::PQTRANS_INERROR).to_s
raised = false
begin
  c.exec_params("SELECT 1", [])
rescue => e
  raised = e.message.include?("transaction is aborted")
end
puts "tx_aborted   " + (raised && c.transaction_status == PG::PQTRANS_INERROR).to_s
c.exec("ROLLBACK")
puts "tx_rollback  " + (c.transaction_status == PG::PQTRANS_IDLE).to_s

# NoData (an INSERT, with a notice on the way) and an empty query
script = [
  auth_ok + ready_idle,
  bmsg("1", "") + bmsg("2", "") + bmsg("n", "") +
  bmsg("N", "S" + "NOTICE" + Z + "M" + "hello" + Z + Z) +
  bmsg("C", "INSERT 0 1" + Z) + ready_idle,
  bmsg("1", "") + bmsg("2", "") + bmsg("n", "") + bmsg("I", "") + ready_idle
]
t = ScriptedTransport.new(script)
c = PgClientCore.new(t, "u", "d", "", "n")
c.connect!
r = c.exec_params("INSERT INTO t (v) VALUES ($1)", ["x"])
puts "xq_nodata    " + (r.nfields == 0 && r.ntuples == 0 && r.cmd_tag == "INSERT 0 1").to_s
r = c.exec_params("", [])
puts "xq_empty_q   " + (r.nfields == 0 && r.ntuples == 0 && r.cmd_tag == "").to_s

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

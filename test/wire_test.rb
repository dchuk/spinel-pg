# Extended-query wire codec, no server: frontend messages byte-exact
# against vectors assembled by hand from the protocol's "Message
# Formats", backend replies cut by PgWireParser and decoded by PgDecode.
# Dual-runtime: no snapshot is committed, so `spin test` diffs the
# compiled run against CRuby directly.
require "pg/wire"

def hex(s)
  [s.delete(" ")].pack("H*")
end

# Byte-exact: once text is non-ASCII, String#== compares encodings too.
def same(a, b)
  a.b == b.b
end

Z = [0].pack("C*")

# --- frontend: Parse / Bind / Describe / Execute / Sync / Close --------------

puts "enc_parse    " + same(PgWire.parse("", "SELECT 1"), hex("50 00000010 00 53454c4543542031 00 0000")).to_s
puts "enc_parse_nm " + same(PgWire.parse("s1", "SELECT $1"), hex("50 00000013 733100 53454c454354202431 00 0000")).to_s

# 129 bytes of SQL put 0x89 in the length prefix: under CRuby, binary
# + non-ASCII UTF-8 raises unless the text joins as bytes.
sql = "SELECT '" + "é" * 60 + "'"
puts "enc_parse_u8 " + same(PgWire.parse("", sql), hex("50 00000089 00") + sql.b + hex("00 0000")).to_s

# portal "", statement "s1", no format codes (all text), 3 params:
# "42", NULL (length -1), "" (length 0); no result format codes.
m = PgWire.bind("", "s1", ["42", nil, ""])
puts "enc_bind     " + same(m, hex("42 0000001c 00 733100 0000 0003 00000002 3432 ffffffff 00000000 0000")).to_s
# portal "p1"; an Integer goes as its to_s
m = PgWire.bind("p1", "s1", [42, nil, ""])
puts "enc_bind_pt  " + same(m, hex("42 0000001e 703100 733100 0000 0003 00000002 3432 ffffffff 00000000 0000")).to_s
puts "enc_bind_mt  " + same(PgWire.bind("", "", []), hex("42 0000000c 00 00 0000 0000 0000")).to_s
v = "é" * 64
puts "enc_bind_u8  " + same(PgWire.bind("", "", [v]), hex("42 00000090 00 00 0000 0001 00000080") + v.b + hex("0000")).to_s
# 65535 parameters is the most a Bind can count (ffff); one more raises
big = [""]
big.delete_at(0)
while big.length < 65535
  big.push("x")
end
m = PgWire.bind("", "", big)
ok = m.bytesize == 327688 && same(m.byteslice(0, 16), hex("42 00050007 00 00 0000 ffff 00000001 78"))
ok = ok && same(m.byteslice(m.bytesize - 7, 7), hex("00000001 78 0000"))
puts "enc_bind_65k " + ok.to_s
big.push("x")
raised = false
begin
  PgWire.bind("", "", big)
rescue => e
  raised = e.message.include?("65535")
end
puts "enc_bind_max " + raised.to_s

puts "enc_desc_p   " + same(PgWire.describe("P", ""), hex("44 00000006 50 00")).to_s
puts "enc_desc_s   " + same(PgWire.describe("S", "s1"), hex("44 00000008 53 733100")).to_s
puts "enc_desc_pt  " + same(PgWire.describe("P", "p1"), hex("44 00000008 50 703100")).to_s
nm = "é" * 64
puts "enc_desc_u8  " + same(PgWire.describe("S", nm), hex("44 00000086 53") + nm.b + hex("00")).to_s
puts "enc_execute  " + same(PgWire.execute("", 0), hex("45 00000009 00 00000000")).to_s
puts "enc_exec_pt  " + same(PgWire.execute("p1", 0), hex("45 0000000b 703100 00000000")).to_s
puts "enc_exec_lim " + same(PgWire.execute("", 100), hex("45 00000009 00 00000064")).to_s
puts "enc_exec_max " + same(PgWire.execute("", 2147483647), hex("45 00000009 00 7fffffff")).to_s
bad = 0
[-1, 2147483648].each do |n|
  begin
    PgWire.execute("", n)
  rescue => e
    if e.message.include?("max_rows")
      bad = bad + 1
    end
  end
end
puts "enc_exec_bad " + (bad == 2).to_s
puts "enc_sync     " + same(PgWire.sync, hex("53 00000004")).to_s
puts "enc_close_s  " + same(PgWire.close("S", "s1"), hex("43 00000008 53 733100")).to_s
puts "enc_close_p  " + same(PgWire.close("P", ""), hex("43 00000006 50 00")).to_s

# --- backend: the extended-query replies, fed byte by byte -------------------

stream = hex("31 00000004") +                                   # ParseComplete
         hex("32 00000004") +                                   # BindComplete
         hex("74 0000000e 0002 00000014 00000019") +            # ParameterDescription: int8, text
         hex("54 00000032 0002" +                               # RowDescription, 2 fields:
             " 696400 00004000 0001 00000014 0008 ffffffff 0000" +    # id: int8
             " 6e616d6500 00004000 0002 00000019 ffff ffffffff 0000") + # name: text
         hex("44 0000000f 0002 00000001 37 ffffffff") +         # DataRow "7", NULL
         hex("43 0000000d 53454c4543542031 00") +               # CommandComplete "SELECT 1"
         hex("5a 00000005 49") +                                # ReadyForQuery, idle
         hex("6e 00000004") +                                   # NoData
         hex("49 00000004") +                                   # EmptyQueryResponse
         hex("73 00000004") +                                   # PortalSuspended
         hex("33 00000004") +                                   # CloseComplete
         hex("5a 00000005 54") +                                # ReadyForQuery, in transaction
         hex("5a 00000005 45")                                  # ReadyForQuery, failed transaction

# byte-at-a-time, so every length and every bodiless message is cut
# across a feed boundary
p = PgWireParser.new
kinds = ""
bodies = [""]
bodies.delete_at(0)
i = 0
while i < stream.bytesize
  p.feed(stream.byteslice(i, 1))
  while p.try_next
    kinds = kinds + p.msg.kind
    bodies.push(p.msg.body)
  end
  i = i + 1
end
puts "dec_kinds    " + (kinds == "12tTDCZnIs3ZZ").to_s
empty = true
[0, 1, 7, 8, 9, 10].each do |k|
  if bodies[k].bytesize != 0
    empty = false
  end
end
puts "dec_bodiless " + empty.to_s
puts "dec_params   " + (PgDecode.param_types(bodies[2]) == [20, 25]).to_s
puts "dec_fields   " + (PgDecode.field_names(bodies[3]) == ["id", "name"]).to_s
puts "dec_ftypes   " + (PgDecode.field_types(bodies[3]) == [20, 25]).to_s
puts "dec_row      " + (PgDecode.row_values(bodies[4], "") == ["7", ""] && PgDecode.row_null_flags(bodies[4]) == [0, 1]).to_s
puts "dec_tag      " + (PgDecode.command_tag(bodies[5]) == "SELECT 1").to_s
s1 = PgDecode.ready_status(bodies[6])
s2 = PgDecode.ready_status(bodies[11])
s3 = PgDecode.ready_status(bodies[12])
puts "dec_ready    " + (s1 == "I" && s2 == "T" && s3 == "E").to_s

# OIDs are unsigned: 0xb2d05e00 is 3000000000, not negative
puts "dec_oid_u32  " + (PgDecode.param_types(hex("0001 b2d05e00")) == [3000000000]).to_s
rd = hex("0001 7800 00000000 0000 b2d05e00 ffff ffffffff 0000")
puts "dec_ftype_u  " + (PgDecode.field_types(rd) == [3000000000]).to_s

# a statement with no parameters, a row with no columns
n1 = PgDecode.param_types(hex("0000")).length
n2 = PgDecode.field_names(hex("0000")).length
n3 = PgDecode.field_types(hex("0000")).length
puts "dec_zero     " + (n1 == 0 && n2 == 0 && n3 == 0).to_s

# --- ErrorResponse fields ------------------------------------------------------

e = "S" + "ERROR" + Z + "V" + "ERROR" + Z + "C" + "23505" + Z +
    "M" + "duplicate key value violates unique constraint \"items_v_key\"" + Z +
    "D" + "Key (v)=(1) already exists." + Z + "n" + "items_v_key" + Z + Z
whole = "E" + PgWire.be32(e.bytesize + 4) + e
p = PgWireParser.new
got = false
i = 0
while i < whole.bytesize
  p.feed(whole.byteslice(i, 1))
  got = p.try_next
  i = i + 1
end
body = p.msg.body
puts "dec_error    " + (got && p.msg.kind == "E").to_s
puts "err_sqlstate " + (PgDecode.error_field(body, "C") == "23505").to_s
puts "err_message  " + (PgDecode.error_field(body, "M") == "duplicate key value violates unique constraint \"items_v_key\"").to_s
puts "err_detail   " + (PgDecode.error_field(body, "D") == "Key (v)=(1) already exists.").to_s
puts "err_constr   " + (PgDecode.error_field(body, "n") == "items_v_key").to_s
puts "err_absent   " + (PgDecode.error_field(body, "H") == "").to_s

# PostgreSQL frontend/backend protocol v3, wire layer: frontend message
# encoding as pure functions, backend messages through an incremental
# parser. Byte-oriented throughout (getbyte / byteslice / bytesize /
# pack) — same discipline as spinel-redis's RESP layer, and the same
# try_next/ivar parser shape (value-or-nil APIs poison spinel call
# sites to poly).
#
# Dependency-free: parity tests run this under CRuby.
#
# Text is UTF-8 both ways. Startup sets client_encoding UTF8; text joins
# a message as bytes (.b: CRuby won't concatenate a length prefix
# holding a byte >= 0x80 with non-ASCII UTF-8); and PgDecode tags the
# text it slices out of the ASCII-8BIT socket bytes as UTF-8, since
# equal non-ASCII bytes in different encodings aren't ==.

module PgWire
  # -- big-endian integer helpers ---------------------------------------

  def self.be32(n)
    [(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff].pack("C*")
  end

  def self.be16(n)
    [(n >> 8) & 0xff, n & 0xff].pack("C*")
  end

  def self.read32(s, i)
    b0 = s.getbyte(i)
    b1 = s.getbyte(i + 1)
    b2 = s.getbyte(i + 2)
    b3 = s.getbyte(i + 3)
    v = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    # int32 is signed on the wire (-1 marks a NULL column length)
    if v >= 2147483648
      v = v - 4294967296
    end
    v
  end

  def self.read16(s, i)
    (s.getbyte(i) << 8) | s.getbyte(i + 1)
  end

  # -- frontend messages -------------------------------------------------

  # StartupMessage: no type byte; length + protocol 3.0 + params.
  def self.startup(user, database)
    body = be32(196608)
    body = body + "user" + zero + user.b + zero
    body = body + "database" + zero + database.b + zero
    body = body + "client_encoding" + zero + "UTF8" + zero
    body = body + zero
    be32(body.bytesize + 4) + body
  end

  # 'p' carries every auth response: cleartext password, SASL initial,
  # SASL continue.
  def self.password_message(payload)
    "p" + be32(payload.bytesize + 4) + payload.b
  end

  def self.cleartext_password(password)
    password_message(password + zero)
  end

  def self.sasl_initial(mechanism, client_first)
    password_message(mechanism + zero + be32(client_first.bytesize) + client_first)
  end

  def self.sasl_response(client_final)
    password_message(client_final)
  end

  # Simple query.
  def self.query(sql)
    "Q" + be32(sql.bytesize + 4 + 1) + sql.b + zero
  end

  def self.terminate
    "X" + be32(4)
  end

  def self.zero
    [0].pack("C*")
  end
end

# One backend message: a type byte and its body. Deliberately flat —
# per-type decoding lives in small pure helpers below rather than a
# class hierarchy.
class PgMsg
  def initialize(kind, body)
    @kind = kind
    @body = body
  end

  # Single-char message type: "R", "S", "K", "Z", "T", "D", "C", "E", "N", ...
  def kind
    @kind
  end

  def body
    @body
  end
end

# Incremental backend-message parser. feed() raw socket bytes;
# try_next() true when a whole message was cut (read it via msg()).
class PgWireParser
  def initialize
    @buf = ""
    @pos = 0
    @msg = PgMsg.new("", "")
  end

  def feed(data)
    @buf = @buf + data
  end

  def buffered_bytes
    @buf.bytesize - @pos
  end

  def msg
    @msg
  end

  def try_next
    avail = @buf.bytesize - @pos
    if avail < 5
      return false
    end
    len = PgWire.read32(@buf, @pos + 1)     # includes itself, not the type byte
    total = len + 1
    if avail < total
      return false
    end
    kind = @buf.byteslice(@pos, 1)
    body = @buf.byteslice(@pos + 5, total - 5)
    @msg = PgMsg.new(kind, body)
    @pos = @pos + total
    if @pos >= 4096
      @buf = @buf.byteslice(@pos, @buf.bytesize - @pos)
      @pos = 0
    end
    true
  end
end

# Per-type body decoding: small pure helpers over PgMsg bodies.
module PgDecode
  # 'R' authentication code: 0 ok, 3 cleartext, 5 md5, 10 SASL,
  # 11 SASL-continue, 12 SASL-final.
  def self.auth_code(body)
    PgWire.read32(body, 0)
  end

  # 'R' code 10: NUL-separated mechanism list. Returns as one string
  # joined with "," (flat and typed; callers just look for a substring).
  def self.sasl_mechanisms(body)
    out = ""
    i = 4
    n = body.bytesize
    start = i
    while i < n
      if body.getbyte(i) == 0
        if i > start
          if out.bytesize > 0
            out = out + ","
          end
          out = out + body.byteslice(start, i - start)
        end
        start = i + 1
      end
      i = i + 1
    end
    out
  end

  # 'R' codes 11/12: the SASL payload is the rest of the body.
  def self.sasl_data(body)
    body.byteslice(4, body.bytesize - 4)
  end

  # 'Z' status byte: "I" idle, "T" in transaction, "E" failed.
  def self.ready_status(body)
    body.byteslice(0, 1)
  end

  # 'T' RowDescription: just the field names (Array<String>); type oids
  # etc. are skipped (text protocol, everything arrives as strings).
  def self.field_names(body)
    names = [""]
    names.delete_at(0)
    nfields = PgWire.read16(body, 0)
    i = 2
    k = 0
    while k < nfields
      start = i
      while body.getbyte(i) != 0
        i = i + 1
      end
      names.push(body.byteslice(start, i - start).force_encoding("UTF-8"))
      i = i + 1            # NUL
      i = i + 18           # tableoid(4) attnum(2) typoid(4) typlen(2) atttypmod(4) format(2)
      k = k + 1
    end
    names
  end

  # 'D' DataRow: column values; a NULL column (length -1) becomes the
  # sentinel handed in (the client layer maps it to nil at its edge).
  def self.row_values(body, null_sentinel)
    vals = [""]
    vals.delete_at(0)
    ncols = PgWire.read16(body, 0)
    i = 2
    k = 0
    while k < ncols
      len = PgWire.read32(body, i)
      i = i + 4
      if len < 0
        vals.push(null_sentinel)
      else
        vals.push(body.byteslice(i, len).force_encoding("UTF-8"))
        i = i + len
      end
      k = k + 1
    end
    vals
  end

  # 'D' again, null bitmap: 1 where the column length was -1. Parallel
  # to row_values so the client can keep values in a flat StrArray and
  # nullness in a flat IntArray (monomorphic storage; nil only at the
  # getvalue edge).
  def self.row_null_flags(body)
    flags = [0]
    flags.delete_at(0)
    ncols = PgWire.read16(body, 0)
    i = 2
    k = 0
    while k < ncols
      len = PgWire.read32(body, i)
      i = i + 4
      if len < 0
        flags.push(1)
      else
        flags.push(0)
        i = i + len
      end
      k = k + 1
    end
    flags
  end

  # 'C' CommandComplete tag ("SELECT 2", "INSERT 0 1", ...).
  def self.command_tag(body)
    i = 0
    n = body.bytesize
    while i < n
      if body.getbyte(i) == 0
        return body.byteslice(0, i).force_encoding("UTF-8")
      end
      i = i + 1
    end
    body
  end

  # 'E'/'N' fields: code byte + cstring, repeated, NUL-terminated list.
  # Returns the field for `code` ("M" message, "S" severity, "C" sqlstate).
  def self.error_field(body, code)
    i = 0
    n = body.bytesize
    while i < n
      c = body.byteslice(i, 1)
      if c == PgWire.zero
        return ""
      end
      start = i + 1
      j = start
      while j < n
        if body.getbyte(j) == 0
          break
        end
        j = j + 1
      end
      if c == code
        return body.byteslice(start, j - start).force_encoding("UTF-8")
      end
      i = j + 1
    end
    ""
  end
end

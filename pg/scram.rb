# SCRAM-SHA-256 (RFC 7677/5802) for PostgreSQL auth, on pure-Ruby
# SHA-256 / HMAC / PBKDF2.
#
# Pure Ruby rather than sp_crypto: every sp_crypto entry point takes
# const char* with strlen semantics, and SCRAM's intermediate keys are
# raw 32-byte digests that routinely contain NULs — the key would
# silently truncate (gap filed upstream). Compiled by spinel this is
# native-code speed, and auth runs once per connection, so PBKDF2's
# 4096 iterations are irrelevant. Binary-safe by construction
# (getbyte / pack), and the whole layer is pure — the parity lane
# pins it to RFC vectors under both runtimes.

module PgSha256
  K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]

  MASK = 0xffffffff

  def self.rotr(x, n)
    ((x >> n) | (x << (32 - n))) & MASK
  end

  # SHA-256 of a binary string, returned as a raw 32-byte string.
  def self.digest(msg)
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    bitlen = msg.bytesize * 8
    padded = msg + [0x80].pack("C*")
    while padded.bytesize % 64 != 56
      padded = padded + [0].pack("C*")
    end
    padded = padded + [
      (bitlen >> 56) & 0xff, (bitlen >> 48) & 0xff, (bitlen >> 40) & 0xff, (bitlen >> 32) & 0xff,
      (bitlen >> 24) & 0xff, (bitlen >> 16) & 0xff, (bitlen >> 8) & 0xff, bitlen & 0xff
    ].pack("C*")

    w = [0] * 64
    block = 0
    nblocks = padded.bytesize / 64
    while block < nblocks
      base = block * 64
      t = 0
      while t < 16
        j = base + t * 4
        w[t] = (padded.getbyte(j) << 24) | (padded.getbyte(j + 1) << 16) |
               (padded.getbyte(j + 2) << 8) | padded.getbyte(j + 3)
        t = t + 1
      end
      while t < 64
        s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
        s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & MASK
        t = t + 1
      end

      a = h0
      b = h1
      c = h2
      d = h3
      e = h4
      f = h5
      g = h6
      h = h7
      t = 0
      while t < 64
        ss1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ ((~e & MASK) & g)
        temp1 = (h + ss1 + ch + K[t] + w[t]) & MASK
        ss0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (ss0 + maj) & MASK
        h = g
        g = f
        f = e
        e = (d + temp1) & MASK
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & MASK
        t = t + 1
      end

      h0 = (h0 + a) & MASK
      h1 = (h1 + b) & MASK
      h2 = (h2 + c) & MASK
      h3 = (h3 + d) & MASK
      h4 = (h4 + e) & MASK
      h5 = (h5 + f) & MASK
      h6 = (h6 + g) & MASK
      h7 = (h7 + h) & MASK
      block = block + 1
    end

    out = [h0, h1, h2, h3, h4, h5, h6, h7]
    bytes = []
    i = 0
    while i < 8
      v = out[i]
      bytes.push((v >> 24) & 0xff)
      bytes.push((v >> 16) & 0xff)
      bytes.push((v >> 8) & 0xff)
      bytes.push(v & 0xff)
      i = i + 1
    end
    bytes.pack("C*")
  end

  # HMAC-SHA-256, raw 32-byte output; key and msg binary-safe.
  def self.hmac(key, msg)
    if key.bytesize > 64
      key = digest(key)
    end
    ik = []
    ok = []
    i = 0
    while i < 64
      b = 0
      if i < key.bytesize
        b = key.getbyte(i)
      end
      ik.push(b ^ 0x36)
      ok.push(b ^ 0x5c)
      i = i + 1
    end
    inner = digest(ik.pack("C*") + msg)
    digest(ok.pack("C*") + inner)
  end

  # PBKDF2-HMAC-SHA-256, single block (dkLen = 32 — all SCRAM needs).
  def self.pbkdf2(password, salt, iterations)
    u = hmac(password, salt + [0, 0, 0, 1].pack("C*"))
    acc = []
    i = 0
    while i < 32
      acc.push(u.getbyte(i))
      i = i + 1
    end
    n = 1
    while n < iterations
      u = hmac(password, u)
      i = 0
      while i < 32
        acc[i] = acc[i] ^ u.getbyte(i)
        i = i + 1
      end
      n = n + 1
    end
    acc.pack("C*")
  end
end

# Standard base64 (RFC 4648, with padding) — the SCRAM wire alphabet.
# Pure, binary-safe.
module PgBase64
  CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

  def self.encode(s)
    out = ""
    i = 0
    n = s.bytesize
    while i + 2 < n
      b0 = s.getbyte(i)
      b1 = s.getbyte(i + 1)
      b2 = s.getbyte(i + 2)
      out = out + CHARS[b0 >> 2] + CHARS[((b0 & 3) << 4) | (b1 >> 4)] +
            CHARS[((b1 & 15) << 2) | (b2 >> 6)] + CHARS[b2 & 63]
      i = i + 3
    end
    rem = n - i
    if rem == 1
      b0 = s.getbyte(i)
      out = out + CHARS[b0 >> 2] + CHARS[(b0 & 3) << 4] + "=="
    elsif rem == 2
      b0 = s.getbyte(i)
      b1 = s.getbyte(i + 1)
      out = out + CHARS[b0 >> 2] + CHARS[((b0 & 3) << 4) | (b1 >> 4)] + CHARS[(b1 & 15) << 2] + "="
    end
    out
  end

  def self.decval(b)
    if b >= 65 && b <= 90
      return b - 65
    end
    if b >= 97 && b <= 122
      return b - 71
    end
    if b >= 48 && b <= 57
      return b + 4
    end
    if b == 43
      return 62
    end
    if b == 47
      return 63
    end
    -1
  end

  def self.decode(s)
    bytes = []
    acc = 0
    nbits = 0
    i = 0
    n = s.bytesize
    while i < n
      v = decval(s.getbyte(i))
      if v >= 0
        acc = (acc << 6) | v
        nbits = nbits + 6
        if nbits >= 8
          nbits = nbits - 8
          bytes.push((acc >> nbits) & 0xff)
          acc = acc & ((1 << nbits) - 1)
        end
      end
      i = i + 1
    end
    bytes.pack("C*")
  end
end

# SCRAM-SHA-256 client state machine. Deterministic by construction:
# the nonce comes in as a parameter, so the parity lane drives it with
# fixed vectors; the live client feeds it randomness.
class PgScram
  # username is "" for PostgreSQL (the server takes identity from the
  # startup message and libpq sends "n=,"); the RFC 7677 vectors carry
  # one, so it stays a parameter.
  def initialize(username, password, client_nonce)
    @password = password
    @cnonce = client_nonce
    @client_first_bare = "n=" + username + ",r=" + client_nonce
    @auth_message = ""
    @server_signature_b64 = ""
    @error = ""
  end

  def error
    @error
  end

  def client_first
    "n,," + @client_first_bare
  end

  # server-first: "r=<nonce>,s=<b64 salt>,i=<iterations>" -> client-final.
  # Returns "" and sets error() on a malformed challenge.
  def client_final(server_first)
    snonce = PgScram.attr_of(server_first, "r")
    salt_b64 = PgScram.attr_of(server_first, "s")
    iters_s = PgScram.attr_of(server_first, "i")
    if snonce.bytesize == 0 || salt_b64.bytesize == 0 || iters_s.bytesize == 0
      @error = "scram: malformed server-first: " + server_first
      return ""
    end
    if snonce.byteslice(0, @cnonce.bytesize) != @cnonce
      @error = "scram: server nonce does not extend client nonce"
      return ""
    end
    salt = PgBase64.decode(salt_b64)
    iters = iters_s.to_i

    salted = PgSha256.pbkdf2(@password, salt, iters)
    client_key = PgSha256.hmac(salted, "Client Key")
    stored_key = PgSha256.digest(client_key)
    without_proof = "c=biws,r=" + snonce
    @auth_message = @client_first_bare + "," + server_first + "," + without_proof
    client_sig = PgSha256.hmac(stored_key, @auth_message)
    proof = []
    i = 0
    while i < 32
      proof.push(client_key.getbyte(i) ^ client_sig.getbyte(i))
      i = i + 1
    end
    server_key = PgSha256.hmac(salted, "Server Key")
    @server_signature_b64 = PgBase64.encode(PgSha256.hmac(server_key, @auth_message))
    without_proof + ",p=" + PgBase64.encode(proof.pack("C*"))
  end

  # server-final: "v=<b64 ServerSignature>" — true iff the server knew
  # the password too.
  def verify_server_final(server_final)
    v = PgScram.attr_of(server_final, "v")
    v == @server_signature_b64
  end

  # "k=v,k2=v2" attribute extraction.
  def self.attr_of(s, name)
    parts = s.split(",")
    i = 0
    while i < parts.length
      part = parts[i]
      if part.bytesize >= 2
        if part.byteslice(0, 2) == name + "="
          return part.byteslice(2, part.bytesize - 2)
        end
      end
      i = i + 1
    end
    ""
  end
end

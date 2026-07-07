# Pure-crypto + SCRAM conformance against published vectors —
# dual-runtime (no snapshot). Correctness comes from the vectors
# (FIPS 180-4, RFC 4231, RFC 7677); the CRuby diff just proves the
# subset behaves identically compiled.
require "pg/scram"

def hex_of(s)
  out = ""
  i = 0
  while i < s.bytesize
    b = s.getbyte(i)
    h = b.to_s(16)
    if h.bytesize == 1
      h = "0" + h
    end
    out = out + h
    i = i + 1
  end
  out
end

# --- SHA-256 (FIPS 180-4 vectors) -------------------------------------------

puts "sha_empty    " + (hex_of(PgSha256.digest("")) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_s
puts "sha_abc      " + (hex_of(PgSha256.digest("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").to_s
puts "sha_448bit   " + (hex_of(PgSha256.digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1").to_s
long = "a" * 200   # crosses multiple 64-byte blocks with padding spill
puts "sha_200a     " + (hex_of(PgSha256.digest(long)) == "c2a908d98f5df987ade41b5fce213067efbcc21ef2240212a41e54b5e7c28ae5").to_s
bin = [0, 255, 1, 254, 128].pack("C*")
puts "sha_binary   " + (hex_of(PgSha256.digest(bin)) == "58b0b60e0b2e5344a54d0290643eca98c041d77f9023433b833ad766d52280a3").to_s

# --- HMAC-SHA-256 (RFC 4231) -------------------------------------------------

key = [11].pack("C*") * 20
puts "hmac_case1   " + (hex_of(PgSha256.hmac(key, "Hi There")) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").to_s
puts "hmac_case2   " + (hex_of(PgSha256.hmac("Jefe", "what do ya want for nothing?")) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843").to_s
# case 3: 20-byte 0xaa key, 50-byte 0xdd data
key = [170].pack("C*") * 20
data = [221].pack("C*") * 50
puts "hmac_case3   " + (hex_of(PgSha256.hmac(key, data)) == "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe").to_s
# key longer than block size (131 bytes of 0xaa)
key = [170].pack("C*") * 131
puts "hmac_bigkey  " + (hex_of(PgSha256.hmac(key, "Test Using Larger Than Block-Size Key - Hash Key First")) == "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54").to_s
# binary key containing NUL — the case sp_crypto's strlen params can't do
key = [1, 0, 2, 0, 3].pack("C*")
puts "hmac_nulkey  " + (PgSha256.hmac(key, "x").bytesize == 32).to_s

# --- PBKDF2-HMAC-SHA-256 ------------------------------------------------------

puts "pbkdf2_i1    " + (hex_of(PgSha256.pbkdf2("password", "salt", 1)) == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b").to_s
puts "pbkdf2_i2    " + (hex_of(PgSha256.pbkdf2("password", "salt", 2)) == "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43").to_s
puts "pbkdf2_i4096 " + (hex_of(PgSha256.pbkdf2("password", "salt", 4096)) == "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a").to_s

# --- base64 -------------------------------------------------------------------

puts "b64_enc      " + (PgBase64.encode("any carnal pleasure.") == "YW55IGNhcm5hbCBwbGVhc3VyZS4=").to_s
puts "b64_enc_pad2 " + (PgBase64.encode("any carnal pleasur") == "YW55IGNhcm5hbCBwbGVhc3Vy").to_s
puts "b64_dec      " + (PgBase64.decode("YW55IGNhcm5hbCBwbGVhc3VyZS4=") == "any carnal pleasure.").to_s
bin = [0, 1, 254, 255, 0, 42].pack("C*")
rt = PgBase64.decode(PgBase64.encode(bin))
ok = rt.bytesize == 6
ok = ok && rt.getbyte(0) == 0
ok = ok && rt.getbyte(3) == 255
puts "b64_bin_rt   " + ok.to_s

# --- SCRAM-SHA-256 (RFC 7677 full exchange) ----------------------------------

sc = PgScram.new("user", "pencil", "rOprNGfwEbeRWgbNEkqO")
puts "scram_first  " + (sc.client_first == "n,,n=user,r=rOprNGfwEbeRWgbNEkqO").to_s
server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
final = sc.client_final(server_first)
puts "scram_final  " + (final == "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=").to_s
puts "scram_verify " + sc.verify_server_final("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=").to_s
puts "scram_badsig " + (!sc.verify_server_final("v=AAAATRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")).to_s

# tampered server nonce must be rejected
sc = PgScram.new("user", "pencil", "rOprNGfwEbeRWgbNEkqO")
bad = sc.client_final("r=XXXXNGfwEbeRWgbNEkqO%hv,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
ok = bad == ""
ok = ok && sc.error.include?("nonce")
puts "scram_nonce  " + ok.to_s

# malformed server-first
sc = PgScram.new("", "pw", "abc")
bad = sc.client_final("garbage")
puts "scram_malformed " + (bad == "" && sc.error.include?("malformed")).to_s

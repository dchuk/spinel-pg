# sp_net + sp_crypto externs. Top-level modules (FFI plumbing must stay
# out of nested modules), distinctly named to coexist with other
# packages' extern modules in one program.
module PgSock
  ffi_func :sp_net_connect,     [:str, :int],       :int
  ffi_func :sp_net_close,       [:int],             :int
  ffi_func :sp_net_write_bytes, [:int, :str, :int], :int
  ffi_func :sp_net_recv_some,   [:int, :int],       :binstr
end

module PgRand
  # SCRAM client nonce. b64url's alphabet is nonce-legal (printable,
  # no comma).
  ffi_func :sp_crypto_random_b64url, [:int], :str
end

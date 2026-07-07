# SCRAM-SHA-256 against a real PostgreSQL: initdb with scram auth and a
# password file, connect over TCP (host auth = scram), verify a wrong
# password is rejected and the right one lands queries. Spinel-only
# (committed snapshot).
require "pg"

module ScramShell
  ffi_func :sp_net_shell_capture, [:str, :int], :binstr
end

def scram_connect_retry(port, db, user, password)
  attempts = 0
  while true
    begin
      c = PG.connect("127.0.0.1", port, db, user, password)   # matz/spinel#1775
      return c
    rescue => e
      # auth failures are terminal, not startup lag
      if e.message.include?("authentication failed")
        raise e.message
      end
      attempts = attempts + 1
      if attempts > 50
        raise "scram live: postgres did not come up on " + port.to_s
      end
      ScramShell.sp_net_shell_capture("sleep 0.2", 16)
    end
  end
end

DIR = "/tmp/spinel-pg-live-scram"
ScramShell.sp_net_shell_capture("pg_ctl -D " + DIR + " stop -m immediate 2>/dev/null; rm -rf " + DIR, 512)
ScramShell.sp_net_shell_capture("echo 's3kr1t-pw' > /tmp/spinel-pg-pwfile && initdb -D " + DIR + " -U scram_user --auth=scram-sha-256 --pwfile=/tmp/spinel-pg-pwfile -N 2>&1 | tail -1", 512)
ScramShell.sp_net_shell_capture("pg_ctl -D " + DIR + " -o '-p 16451 -c listen_addresses=127.0.0.1 -c unix_socket_directories=" + DIR + "' -l " + DIR + "/log start 2>&1 | tail -1", 512)

c = scram_connect_retry(16451, "postgres", "scram_user", "s3kr1t-pw")
puts "scram_auth   " + c.ready?.to_s

r = c.exec("SELECT current_user")
puts "current_user " + r.getvalue(0, 0).to_s
r = c.exec("SELECT 7 * 6")
puts "query        " + r.getvalue(0, 0).to_s
c.close

# wrong password: the server must reject the proof
rejected = false
begin
  PG.connect("127.0.0.1", 16451, "postgres", "scram_user", "wrong-pw")
rescue => e
  rejected = e.message.include?("authentication failed")
end
puts "bad_pw       " + rejected.to_s

ScramShell.sp_net_shell_capture("pg_ctl -D " + DIR + " stop -m immediate 2>&1 | tail -1; rm -rf " + DIR + " /tmp/spinel-pg-pwfile", 512)
puts "done"

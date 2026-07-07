# End-to-end against a real PostgreSQL (trust auth), spinel-only
# (committed snapshot; the ffi graph can't load under CRuby). The test
# owns its instance: initdb into a throwaway dir, private port, torn
# down at the end. Needs initdb/pg_ctl/postgres on PATH (brew:
# /opt/homebrew/opt/postgresql@17/bin).
require "pg"

module PgShell
  ffi_func :sp_net_shell_capture, [:str, :int], :binstr
end

def pg_connect_retry(port, db, user, password)
  attempts = 0
  while true
    begin
      c = PG.connect("127.0.0.1", port, db, user, password)   # matz/spinel#1775: assign-then-return
      return c
    rescue
      attempts = attempts + 1
      if attempts > 50
        raise "live: postgres did not come up on " + port.to_s
      end
      PgShell.sp_net_shell_capture("sleep 0.2", 16)
    end
  end
end

DIR = "/tmp/spinel-pg-live-trust"
PgShell.sp_net_shell_capture("pg_ctl -D " + DIR + " stop -m immediate 2>/dev/null; rm -rf " + DIR, 512)
PgShell.sp_net_shell_capture("initdb -D " + DIR + " -U spinel_test --auth=trust -N 2>&1 | tail -1", 512)
PgShell.sp_net_shell_capture("pg_ctl -D " + DIR + " -o '-p 16450 -c listen_addresses=127.0.0.1 -c unix_socket_directories=" + DIR + "' -l " + DIR + "/log start 2>&1 | tail -1", 512)

c = pg_connect_retry(16450, "postgres", "spinel_test", "")
puts "connected    " + c.ready?.to_s

r = c.exec("SELECT 1 AS one, 'hello' AS greet")
puts "select_basic " + (r.ntuples == 1 && r.getvalue(0, 0) == "1" && r.getvalue(0, 1) == "hello").to_s
puts "fields       " + r.fields.join(",")

r = c.exec("CREATE TABLE accounts (id serial PRIMARY KEY, name text, note text)")
puts "create_tag   " + r.cmd_tag

r = c.exec("INSERT INTO accounts (name, note) VALUES ('alice', 'first'), ('bob', NULL)")
puts "insert_tag   " + r.cmd_tag

r = c.exec("SELECT id, name, note FROM accounts ORDER BY id")
puts "rows         " + r.ntuples.to_s
puts "row0         " + r.getvalue(0, 0).to_s + ":" + r.getvalue(0, 1).to_s + ":" + r.getvalue(0, 2).to_s
n = r.getvalue(1, 2)
puts "null_note    " + n.nil?.to_s

r = c.exec("UPDATE accounts SET note = 'seen' WHERE name = 'bob'")
puts "update_tag   " + r.cmd_tag

# utf-8 round trip through the text protocol
r = c.exec("SELECT 'héllo→wörld' AS u")
puts "utf8         " + (r.getvalue(0, 0) == "héllo→wörld").to_s

# the streaming server's actual auth-query shape
r = c.exec("SELECT count(*) FROM accounts WHERE note IS NULL")
puts "count_null   " + r.getvalue(0, 0).to_s

# server error surfaces with severity + message, connection stays usable
raised = false
begin
  c.exec("SELECT * FROM no_such_table")
rescue => e
  raised = e.message.include?("does not exist")
end
puts "err_raises   " + raised.to_s
r = c.exec("SELECT 42")
puts "err_recovers " + (r.getvalue(0, 0) == "42").to_s

c.close
PgShell.sp_net_shell_capture("pg_ctl -D " + DIR + " stop -m immediate 2>&1 | tail -1; rm -rf " + DIR, 512)
puts "done"

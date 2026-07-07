# Query client over an injected transport duck (write / read_some /
# close) — same architecture as spinel-redis's RedisClientCore: the
# protocol logic tests dual-runtime against a scripted transport, the
# real sp_net transport stays in the compiled-only lanes.
#
# Simple-query protocol only (text results): that's the whole surface
# the streaming server's auth queries need, and the honest v0.1 of the
# eventual ActiveRecord seam. Extended protocol / COPY / notifications
# are ledgered in the README.
require "pg/wire"
require "pg/scram"

# One query's result. Storage is flat and monomorphic — values in one
# StrArray with a parallel null-flag IntArray — and nil appears only at
# the getvalue edge (the redis-rb-proven String|nil contract).
class PgResult
  def initialize(fields, values, nulls, tag)
    @fields = fields
    @values = values
    @nulls = nulls
    @tag = tag
  end

  def fields
    @fields
  end

  def nfields
    @fields.length
  end

  def ntuples
    if @fields.length == 0
      return 0
    end
    @values.length / @fields.length
  end

  def cmd_tag
    @tag
  end

  def getvalue(row, col)
    idx = row * @fields.length + col
    if idx < 0 || idx >= @values.length
      return nil
    end
    if @nulls[idx] == 1
      return nil
    end
    @values[idx]
  end
end

class PgClientCore
  def initialize(transport, user, database, password, scram_nonce)
    @t = transport
    @user = user
    @database = database
    @password = password
    @nonce = scram_nonce
    @parser = PgWireParser.new
    @ready = false
  end

  def ready?
    @ready
  end

  def close
    @t.write(PgWire.terminate)
    @t.close
  end

  # -- plumbing ----------------------------------------------------------

  def read_msg
    while true
      if @parser.try_next
        return @parser.msg
      end
      chunk = @t.read_some(65536)
      if chunk.bytesize == 0
        raise "pg: connection lost"
      end
      @parser.feed(chunk)
    end
  end

  def raise_error(body)
    sev = PgDecode.error_field(body, "S")
    msg = PgDecode.error_field(body, "M")
    raise "pg: " + sev + ": " + msg
  end

  # -- startup / auth ------------------------------------------------------

  # Drive startup to ReadyForQuery. Handles trust (immediate ok),
  # cleartext password, and SCRAM-SHA-256. MD5 is deliberately not
  # implemented (ledgered; modern servers default to SCRAM).
  def connect!
    @t.write(PgWire.startup(@user, @database))
    scram = PgScram.new("", @password, @nonce)
    while true
      m = read_msg
      if m.kind == "R"
        code = PgDecode.auth_code(m.body)
        if code == 0
          # authenticated; fall through to parameter/ready messages
        elsif code == 3
          @t.write(PgWire.cleartext_password(@password))
        elsif code == 10
          mechs = PgDecode.sasl_mechanisms(m.body)
          if !mechs.include?("SCRAM-SHA-256")
            raise "pg: server offers no supported SASL mechanism (" + mechs + ")"
          end
          @t.write(PgWire.sasl_initial("SCRAM-SHA-256", scram.client_first))
        elsif code == 11
          final = scram.client_final(PgDecode.sasl_data(m.body))
          if final.bytesize == 0
            raise "pg: " + scram.error
          end
          @t.write(PgWire.sasl_response(final))
        elsif code == 12
          if !scram.verify_server_final(PgDecode.sasl_data(m.body))
            raise "pg: server signature verification failed"
          end
        elsif code == 5
          raise "pg: md5 auth not supported (configure scram-sha-256 or password)"
        else
          raise "pg: unsupported auth request code " + code.to_s
        end
      elsif m.kind == "E"
        raise_error(m.body)
      elsif m.kind == "Z"
        @ready = true
        return 0
      end
      # "S" ParameterStatus / "K" BackendKeyData / "N" notices: ignored
    end
  end

  # -- queries ---------------------------------------------------------------

  # Simple query, text results. Multi-statement strings work (last
  # result wins — enough for v0.1; ledgered).
  def exec(sql)
    @t.write(PgWire.query(sql))
    fields = [""]
    fields.delete_at(0)
    values = [""]
    values.delete_at(0)
    nulls = [0]
    nulls.delete_at(0)
    tag = ""
    err_body = ""
    failed = false
    while true
      m = read_msg
      if m.kind == "T"
        fields = PgDecode.field_names(m.body)
        values.delete_at(0) while values.length > 0
        nulls.delete_at(0) while nulls.length > 0
      elsif m.kind == "D"
        row = PgDecode.row_values(m.body, "")
        # Parallel null flags: row_values hands back "" for NULL with a
        # second pass marking which were genuinely null.
        flags = PgDecode.row_null_flags(m.body)
        i = 0
        while i < row.length
          values.push(row[i])
          nulls.push(flags[i])
          i = i + 1
        end
      elsif m.kind == "C"
        tag = PgDecode.command_tag(m.body)
      elsif m.kind == "E"
        err_body = m.body
        failed = true
      elsif m.kind == "Z"
        if failed
          raise_error(err_body)
        end
        return PgResult.new(fields, values, nulls, tag)
      end
      # "N" notices / "S" parameter changes: ignored
    end
  end
end

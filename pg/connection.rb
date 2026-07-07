# The real transport: TCP to a PostgreSQL server over sp_net. Same
# duck as the scripted test transport (write / read_some / close).
require "pg/sock"

class PgTransport
  def initialize(host, port)
    @fd = PgSock.sp_net_connect(host, port)
    if @fd < 0
      raise "pg: cannot connect to " + host + ":" + port.to_s
    end
  end

  def fd
    @fd
  end

  def write(data)
    PgSock.sp_net_write_bytes(@fd, data, data.bytesize)
  end

  def read_some(max)
    PgSock.sp_net_recv_some(@fd, max)
  end

  def close
    PgSock.sp_net_close(@fd)
  end
end

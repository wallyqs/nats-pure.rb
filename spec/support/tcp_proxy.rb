# frozen_string_literal: true

require "socket"

# Forwards the TCP connections made to a local port to a server, keeping
# the bytes that went through each way, for specs that look at the wire.
class TCPProxy
  Conn = Struct.new(:up, :down)

  attr_reader :port

  def initialize(port, target_port, target_host = "127.0.0.1")
    @port = port
    @target_port = target_port
    @target_host = target_host
    @conns = []
    @sockets = []
    @lock = Mutex.new
  end

  def start
    @server = TCPServer.new("127.0.0.1", @port)
    @thread = Thread.new do
      loop do
        client = @server.accept
        upstream = TCPSocket.new(@target_host, @target_port)
        conn = Conn.new(+"".b, +"".b)
        @lock.synchronize do
          @conns << conn
          @sockets.push(client, upstream)
        end
        pipe(client, upstream, conn.up)
        pipe(upstream, client, conn.down)
      rescue IOError, SystemCallError
        break if @server.closed?
      end
    end
    self
  end

  # The connections made so far, each with the bytes that the client sent
  # (up) and that it got (down).
  def conns
    @lock.synchronize { @conns.dup }
  end

  # Closes the open connections, keeping the listener.
  def drop_connections
    @lock.synchronize do
      @sockets.each { |s| s.close unless s.closed? }
      @sockets.clear
    end
  end

  def stop
    @server&.close
    @thread&.join(1)
    drop_connections
  end

  private

  def pipe(from, to, log)
    Thread.new do
      loop do
        data = from.readpartial(65536)
        @lock.synchronize { log << data }
        to.write(data)
      end
    rescue IOError, SystemCallError
      [from, to].each { |s| s.close unless s.closed? }
    end
  end
end

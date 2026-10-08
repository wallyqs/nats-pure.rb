# frozen_string_literal: true

require "socket"

describe "Client - client ID and IP" do
  before(:all) do
    @server = NatsServerControl.new("nats://127.0.0.1:4935", "/tmp/test-nats-4935.pid", "-a 127.0.0.1")
    @server.start_server(true)
  end

  after(:all) { @server.kill_server }

  # A server that answers like nats-server, but with an INFO without the
  # client_id and client_ip of servers before v1.2.0 and v2.1.6.
  def start_old_server
    tcp = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      conn = tcp.accept
      conn.write(%(INFO {"server_id":"old","version":"1.1.0","proto":1,"max_payload":1048576}\r\n))
      while (line = conn.gets)
        conn.write("PONG\r\n") if line.start_with?("PING")
      end
    rescue IOError, SystemCallError
      nil
    ensure
      conn&.close
    end
    [tcp, thread]
  end

  it "should return the id and IP that the server tells" do
    nc = NATS.connect("nats://127.0.0.1:4935", reconnect: false)
    expect(nc.client_id).to be_a(Integer)
    expect(nc.client_id).to eql(nc.server_info[:client_id])
    expect(nc.client_ip).to be_a(IPAddr)
    expect(nc.client_ip).to eql(IPAddr.new("127.0.0.1"))
    expect(nc.client_ip.to_s).to eql(nc.server_info[:client_ip])
    nc.close

    expect { nc.client_id }.to raise_error(NATS::IO::ConnectionClosedError)
    expect { nc.client_ip }.to raise_error(NATS::IO::ConnectionClosedError)
  end

  it "should raise ClientIDNotSupported and ClientIPNotSupported when the server does not tell them" do
    tcp, thread = start_old_server
    nc = NATS.connect("nats://127.0.0.1:#{tcp.addr[1]}", reconnect: false)
    expect(nc.connected_server_id).to eql("old")
    expect { nc.client_id }.to raise_error(NATS::IO::ClientIDNotSupported, "nats: client ID not supported by this server")
    expect { nc.client_ip }.to raise_error(NATS::IO::ClientIPNotSupported, "nats: client IP not supported by this server")
    expect(NATS::IO::ClientIDNotSupported.ancestors).to include(NATS::IO::ClientError)
    nc.close
  ensure
    tcp&.close
    thread&.join(2)
  end

  it "should raise them before the client connected" do
    nc = NATS::IO::Client.new
    expect { nc.client_id }.to raise_error(NATS::IO::ClientIDNotSupported)
    expect { nc.client_ip }.to raise_error(NATS::IO::ClientIPNotSupported)
  end
end

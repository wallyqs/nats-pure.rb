# frozen_string_literal: true

describe "Client - connect timeout" do
  context "against a server that does not accept connections" do
    before(:all) do
      # A listener whose accept queue is full: the kernel drops further SYNs,
      # so dialing it hangs until the client gives up.
      @listener = Socket.new(:INET, :STREAM)
      @listener.bind(Addrinfo.tcp("127.0.0.1", 4870))
      @listener.listen(0)
      @backlog = []
      4.times do
        s = Socket.new(:INET, :STREAM)
        begin
          s.connect_nonblock(Socket.pack_sockaddr_in(4870, "127.0.0.1"))
        rescue IO::WaitWritable
          IO.select(nil, [s], nil, 0.2)
        end
        @backlog << s
      end
    end

    after(:all) do
      @backlog.each(&:close)
      @listener.close
    end

    it "should give up dialing after connect_timeout" do
      nc = NATS::IO::Client.new
      started = NATS::MonotonicTime.now
      expect do
        nc.connect(servers: ["nats://127.0.0.1:4870"], reconnect: false, connect_timeout: 0.3)
      end.to raise_error(NATS::IO::SocketTimeoutError, /timeout dialing/)
      elapsed = NATS::MonotonicTime.since(started)
      expect(elapsed).to be >= 0.3
      # The default of 2 seconds used to bound every dial.
      expect(elapsed).to be < 1.5
    end

    it "should wait up to connect_timeout when it is longer than the default" do
      nc = NATS::IO::Client.new
      started = NATS::MonotonicTime.now
      expect do
        nc.connect(servers: ["nats://127.0.0.1:4870"], reconnect: false, connect_timeout: 2.5)
      end.to raise_error(NATS::IO::SocketTimeoutError)
      expect(NATS::MonotonicTime.since(started)).to be >= 2.5
    end
  end

  context "against a server that never completes the TLS handshake" do
    before(:all) do
      @fake_nats_server = TCPServer.new 4871
      @clients = []
      @fake_nats_server_th = Thread.new do
        loop do
          client = @fake_nats_server.accept
          client.write %(INFO {"version":"2.10.0","proto":1,"tls_required":true,"max_payload":1048576}\r\n)
          # Linger without ever answering the ClientHello.
          @clients << client
        rescue IOError
          break if @fake_nats_server.closed?
        end
      end
    end

    after(:all) do
      @fake_nats_server_th.exit
      @fake_nats_server.close
      @clients.each(&:close)
    end

    it "should give up the TLS handshake after connect_timeout" do
      nc = NATS::IO::Client.new
      started = NATS::MonotonicTime.now
      expect do
        ctx = OpenSSL::SSL::SSLContext.new
        ctx.set_params
        nc.connect(servers: ["tls://127.0.0.1:4871"], reconnect: false, connect_timeout: 0.5, tls: {context: ctx})
      end.to raise_error(NATS::IO::SocketTimeoutError, /TLS handshake/)
      elapsed = NATS::MonotonicTime.since(started)
      expect(elapsed).to be >= 0.5
      expect(elapsed).to be < 2
    end
  end

  context "against a nats-server" do
    before(:all) do
      @s = NatsServerControl.new("nats://127.0.0.1:4872", "/tmp/test-nats.pid")
      @s.start_server(true)
    end

    after(:all) do
      @s.kill_server
    end

    it "should connect with a custom connect_timeout" do
      nc = NATS.connect(@s.uri, connect_timeout: 0.5)
      expect(nc.options[:connect_timeout]).to eql(0.5)
      nc.flush
      expect(nc).to be_connected
      nc.close
    end
  end
end

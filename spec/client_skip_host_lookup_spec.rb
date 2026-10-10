# frozen_string_literal: true

describe "Client - skip_host_lookup" do
  before(:all) do
    @port = 4798
    @server = NatsServerControl.new("nats://127.0.0.1:#{@port}", "/tmp/test-nats-skip-lookup.pid", "-a 127.0.0.1")
    @server.start_server(true)
  end

  after(:all) { @server.kill_server }

  def round_trip(nc)
    nc.subscribe("lookup") { |msg| msg.respond("ok") }
    nc.request("lookup", "", timeout: 2).data
  end

  it "resolves the host name and dials its addresses by default" do
    expect(::Socket).to receive(:getaddrinfo).with("localhost", any_args).at_least(:once).and_call_original
    nc = NATS.connect("nats://localhost:#{@port}", reconnect: false)
    expect(round_trip(nc)).to eq("ok")
    nc.close
  end

  it "connects to the host name as it is, like nats.go" do
    expect(::Socket).not_to receive(:getaddrinfo)
    nc = NATS.connect("nats://localhost:#{@port}", reconnect: false, skip_host_lookup: true)
    expect(round_trip(nc)).to eq("ok")
    expect(nc.connected_addr).to eq("127.0.0.1:#{@port}")
    nc.close
  end

  it "hands the custom dialer the host name" do
    hosts = []
    dialer = lambda do |host, port, timeout|
      hosts << host
      TCPSocket.new("127.0.0.1", port, connect_timeout: timeout)
    end
    expect(::Socket).not_to receive(:getaddrinfo)
    nc = NATS.connect("nats://localhost:#{@port}", reconnect: false, skip_host_lookup: true, custom_dialer: dialer)
    expect(round_trip(nc)).to eq("ok")
    expect(hosts).to eq(["localhost"])
    nc.close
  end

  it "fails as connect does for a host name that does not resolve" do
    expect do
      NATS.connect("nats://nats.invalid:#{@port}", reconnect: false, skip_host_lookup: true)
    end.to raise_error(SocketError)
  end

  context "against a server that does not accept connections" do
    before(:all) do
      # A listener whose accept queue is full, so that dialing it hangs.
      @listener = Socket.new(:INET, :STREAM)
      @listener.bind(Addrinfo.tcp("127.0.0.1", 4799))
      @listener.listen(0)
      @backlog = 4.times.map do
        s = Socket.new(:INET, :STREAM)
        begin
          s.connect_nonblock(Socket.pack_sockaddr_in(4799, "127.0.0.1"))
        rescue IO::WaitWritable
          IO.select(nil, [s], nil, 0.2)
        end
        s
      end
    end

    after(:all) do
      @backlog.each(&:close)
      @listener.close
    end

    it "gives up dialing after connect_timeout" do
      started = NATS::MonotonicTime.now
      expect do
        NATS.connect("nats://127.0.0.1:4799", reconnect: false, skip_host_lookup: true, connect_timeout: 0.3)
      end.to raise_error(NATS::IO::SocketTimeoutError, /timeout dialing/)
      expect(NATS::MonotonicTime.since(started)).to be_between(0.3, 1.5)
    end
  end
end

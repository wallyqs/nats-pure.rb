# frozen_string_literal: true

describe "Client - custom dialer" do
  before(:all) do
    @port = 4796
    @server = NatsServerControl.new("nats://127.0.0.1:#{@port}", "/tmp/test-nats-dialer.pid", "-a 127.0.0.1")
    @server.start_server(true)
  end

  after(:all) { @server.kill_server }

  def round_trip(nc)
    nc.subscribe("dialer") { |msg| msg.respond("ok:#{msg.data}") }
    nc.request("dialer", "hi", timeout: 2).data
  end

  it "dials with a Proc given the host, port and connect timeout" do
    calls = Queue.new
    dialer = proc do |host, port, timeout|
      calls << [host, port, timeout]
      TCPSocket.new(host, port, connect_timeout: timeout)
    end
    nc = NATS.connect("nats://127.0.0.1:#{@port}", custom_dialer: dialer, connect_timeout: 1.5)
    expect(round_trip(nc)).to eq("ok:hi")
    expect(calls.pop(true)).to eq(["127.0.0.1", @port, 1.5])

    # And again to reconnect.
    reconnected = Queue.new
    nc.on_reconnect { reconnected << true }
    nc.force_reconnect
    Timeout.timeout(5) { reconnected.pop }
    expect(calls.pop(true)).to eq(["127.0.0.1", @port, 1.5])
    expect(round_trip(nc)).to eq("ok:hi")
    nc.close
  end

  it "dials with an object that responds to dial, which decides where to connect" do
    # Like a dialer that goes through a tunnel: the URL is not reachable.
    dialer = Object.new
    real_port = @port
    dialer.define_singleton_method(:dial) do |_host, _port, timeout|
      TCPSocket.new("127.0.0.1", real_port, connect_timeout: timeout)
    end
    nc = NATS.connect("nats://127.0.0.1:1", custom_dialer: dialer, reconnect: false)
    expect(round_trip(nc)).to eq("ok:hi")
    expect(nc.connected_url_redacted).to eq("nats://127.0.0.1:1")
    nc.close
  end

  it "tries each address that the host name resolves to, like nats.go" do
    hosts = []
    dialer = lambda do |host, port, timeout|
      hosts << host
      raise Errno::ECONNREFUSED if host != "127.0.0.1"

      TCPSocket.new(host, port, connect_timeout: timeout)
    end
    allow(::Socket).to receive(:getaddrinfo).and_call_original
    allow(::Socket).to receive(:getaddrinfo).with("nats.example", any_args).and_return([
      ["AF_INET6", 0, "::1", "::1", ::Socket::AF_INET6, ::Socket::SOCK_STREAM, 6],
      ["AF_INET", 0, "127.0.0.1", "127.0.0.1", ::Socket::AF_INET, ::Socket::SOCK_STREAM, 6]
    ])
    nc = NATS.connect("nats://nats.example:#{@port}", custom_dialer: dialer, reconnect: false)
    expect(hosts).to eq(["::1", "127.0.0.1"])
    expect(round_trip(nc)).to eq("ok:hi")
    nc.close
  end

  it "fails the connect with what the dialer raises" do
    dialer = ->(_host, _port, _timeout) { raise Errno::EHOSTUNREACH }
    expect do
      NATS.connect("nats://127.0.0.1:#{@port}", custom_dialer: dialer, reconnect: false)
    end.to raise_error(Errno::EHOSTUNREACH)
  end

  it "refuses a dialer that can neither dial nor be called" do
    expect do
      NATS.connect("nats://127.0.0.1:#{@port}", custom_dialer: Object.new, reconnect: false)
    end.to raise_error(ArgumentError, /custom_dialer must respond to dial or call/)
  end

  context "with a dialer that does the TLS handshake" do
    before(:all) do
      config = %(
        net: "127.0.0.1"
        port: 4797
        tls {
          cert_file: "./spec/configs/certs/server.pem"
          key_file:  "./spec/configs/certs/key.pem"
          timeout:   5
          handshake_first: true
        }
      )
      opts = {"pid_file" => "/tmp/test-nats-dialer-tls.pid", "host" => "127.0.0.1", "port" => 4797}
      @tls_server = NatsServerControl.init_with_config_from_string(config, opts).tap(&:start_server)
    end

    after(:all) { @tls_server.kill_server }

    it "skips the TLS handshake of the client when it says so with skip_tls_handshake?" do
      dialer = Object.new
      def dialer.skip_tls_handshake? = true

      def dialer.dial(host, port, timeout)
        ctx = OpenSSL::SSL::SSLContext.new
        ctx.set_params
        ctx.ca_file = "./spec/configs/certs/ca.pem"
        tls = OpenSSL::SSL::SSLSocket.new(TCPSocket.new(host, port, connect_timeout: timeout), ctx)
        tls.sync_close = true
        tls.hostname = "localhost"
        tls.connect
        tls
      end

      nc = NATS.connect("tls://127.0.0.1:4797", custom_dialer: dialer, reconnect: false)
      expect(round_trip(nc)).to eq("ok:hi")
      nc.close
    end
  end
end

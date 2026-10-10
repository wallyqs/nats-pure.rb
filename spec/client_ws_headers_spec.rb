# frozen_string_literal: true

describe "Client - WebSocket connection headers" do
  let(:host) { "127.0.0.1" }
  let(:port) { 4792 }
  let(:ws_port) { 8792 }
  let(:proxy_port) { 8793 }
  let(:url) { "ws://#{host}:#{proxy_port}" }

  # The server takes the token from a cookie of the upgrade request.
  before do
    config = <<~CONF
      net: "#{host}"
      port: #{port}
      authorization { token: "s3cr3t" }
      websocket {
        port: #{ws_port}
        no_tls: true
        token_cookie: "nats_token"
      }
    CONF
    @natsctl = NatsServerControl.init_with_config_from_string(config, {
      "pid_file" => "/tmp/test-nats-ws-headers.pid", "host" => host, "port" => port
    })
    @natsctl.start_server(true)
    @proxy = TCPProxy.new(proxy_port, ws_port).start
  end

  after do
    @proxy.stop
    @natsctl.kill_server
  end

  def request_of(conn)
    conn.up[0, conn.up.index("\r\n\r\n")]
  end

  it "sends the static headers with the upgrade request" do
    nc = NATS.connect(url, reconnect: false, ws_headers: {
      "Cookie" => "nats_token=s3cr3t",
      "X-Multi" => ["a", "b"]
    })
    expect(nc.connected?).to be(true)
    nc.subscribe("hello") { |msg| msg.respond("hi") }
    expect(nc.request("hello", "", timeout: 2).data).to eq("hi")

    request = request_of(@proxy.conns.first)
    expect(request).to include("\r\nCookie: nats_token=s3cr3t")
    expect(request).to include("\r\nX-Multi: a\r\nX-Multi: b")
    nc.close
  end

  it "fails without the headers that the server needs" do
    expect do
      NATS.connect(url, reconnect: false)
    end.to raise_error(NATS::IO::AuthError)
  end

  it "calls the handler for the headers on every connect" do
    calls = 0
    handler = proc do
      calls += 1
      {"Cookie" => "nats_token=s3cr3t", "X-Attempt" => calls.to_s}
    end
    nc = NATS.connect(url, ws_headers_handler: handler, reconnect_time_wait: 0.1, max_reconnect_attempts: -1)
    reconnected = Queue.new
    nc.on_reconnect { reconnected << true }

    @proxy.drop_connections
    Timeout.timeout(5) { reconnected.pop }
    nc.flush

    expect(calls).to eq(2)
    expect(request_of(@proxy.conns[0])).to include("X-Attempt: 1")
    expect(request_of(@proxy.conns[1])).to include("X-Attempt: 2")
    nc.close
  end

  it "fails the connect with what the handler raises" do
    errors = []
    nc = NATS::IO::Client.new
    nc.on_error { |e| errors << e }
    expect do
      nc.connect(url, reconnect: false, ws_headers_handler: -> { raise IOError, "no token" })
    end.to raise_error(IOError, "no token")
    expect(errors.map(&:message)).to eq(["no token"])
  end

  it "refuses headers that would break the request" do
    expect do
      NATS.connect(url, reconnect: false, ws_headers: {"X-Evil" => "a\r\nCookie: nats_token=s3cr3t"})
    end.to raise_error(NATS::IO::WebSocket::HandshakeError, /invalid websocket connection header/)
  end

  it "refuses both static headers and a handler, like nats.go" do
    expect do
      NATS.connect(url, reconnect: false, ws_headers: {"A" => "b"}, ws_headers_handler: -> { {} })
    end.to raise_error(ArgumentError, "nats: websocket connection headers already set")

    expect do
      NATS.connect(url, reconnect: false, ws_headers_handler: "nope")
    end.to raise_error(ArgumentError, /ws_headers_handler must respond to call/)
  end
end

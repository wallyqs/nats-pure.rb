# frozen_string_literal: true

describe "Client - WebSocket compression" do
  let(:host) { "127.0.0.1" }
  let(:port) { 4790 }
  let(:ws_port) { 8790 }
  let(:proxy_port) { 8791 }
  let(:server_compression) { true }

  before do
    config = <<~CONF
      net: "#{host}"
      port: #{port}
      websocket {
        port: #{ws_port}
        no_tls: true
        compression: #{server_compression}
      }
    CONF
    @natsctl = NatsServerControl.init_with_config_from_string(config, {
      "pid_file" => "/tmp/test-nats-ws-compression.pid", "host" => host, "port" => port
    })
    @natsctl.start_server(true)
    @proxy = TCPProxy.new(proxy_port, ws_port).start
  end

  after do
    @proxy.stop
    @natsctl.kill_server
  end

  def ws_io(nc)
    nc.instance_variable_get(:@io)
  end

  # Publishes data to itself and returns what it gets back.
  def round_trip(nc, data)
    msgs = Queue.new
    nc.subscribe("compressed") { |msg| msgs << msg.data }
    nc.flush
    nc.publish("compressed", data)
    nc.flush
    Timeout.timeout(5) { msgs.pop }
  end

  it "compresses the messages both ways when the server agrees to" do
    nc = NATS.connect("ws://#{host}:#{proxy_port}", compression: true, reconnect: false)
    expect(ws_io(nc).compressed?).to be(true)

    data = "x" * 512 * 1024
    expect(round_trip(nc, data)).to eq(data)

    # What the payload would take uncompressed, once each way.
    conn = @proxy.conns.first
    expect(conn.up).to include("Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover")
    expect(conn.up.bytesize).to be < 64 * 1024
    expect(conn.down.bytesize).to be < 64 * 1024

    # Messages of all sizes, binary or not, and requests work too.
    nc.subscribe("help") { |msg| msg.respond("I can help #{msg.data}") }
    ["", "a", "héllo wörld", Random.new(1).bytes(70_000).b, "y" * 200_000].each do |payload|
      expect(round_trip(nc, payload).b).to eq(payload.b)
    end
    expect(nc.request("help", "now", timeout: 2).data).to eq("I can help now")

    nc.close
  end

  context "when the server does not compress" do
    let(:server_compression) { false }

    it "goes on uncompressed, like nats.go" do
      nc = NATS.connect("ws://#{host}:#{proxy_port}", compression: true, reconnect: false)
      expect(ws_io(nc).compressed?).to be(false)

      data = "x" * 64 * 1024
      expect(round_trip(nc, data)).to eq(data)
      expect(@proxy.conns.first.down.bytesize).to be > 64 * 1024

      nc.close
    end
  end

  it "does not ask for compression by default" do
    nc = NATS.connect("ws://#{host}:#{proxy_port}", reconnect: false)
    expect(ws_io(nc).compressed?).to be(false)
    expect(@proxy.conns.first.up).not_to include("Sec-WebSocket-Extensions")

    data = "x" * 64 * 1024
    expect(round_trip(nc, data)).to eq(data)
    expect(@proxy.conns.first.down.bytesize).to be > 64 * 1024

    nc.close
  end

  it "compresses again after a reconnect" do
    nc = NATS.connect("ws://#{host}:#{proxy_port}", compression: true, reconnect_time_wait: 0.1, max_reconnect_attempts: -1)
    reconnected = Queue.new
    nc.on_reconnect { reconnected << true }

    @proxy.drop_connections
    Timeout.timeout(5) { reconnected.pop }

    expect(ws_io(nc).compressed?).to be(true)
    data = "z" * 256 * 1024
    expect(round_trip(nc, data)).to eq(data)
    expect(@proxy.conns.last.down.bytesize).to be < 64 * 1024

    nc.close
  end
end

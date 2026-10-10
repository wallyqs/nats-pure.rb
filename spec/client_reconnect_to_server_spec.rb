# frozen_string_literal: true

describe "Client - reconnect_to_server" do
  let(:urls) { %w[nats://127.0.0.1:4921 nats://127.0.0.1:4922 nats://127.0.0.1:4923] }

  before do
    @servers = urls.map { |url| NatsServerControl.new(url, "/tmp/test-nats-#{URI(url).port}.pid") }
    @servers.each { |s| s.start_server(true) }
  end

  after do
    @servers.each(&:kill_server)
  end

  # Connects to the first server, with the others in the pool after it.
  def connect(**opts)
    nc = NATS::IO::Client.new
    errors = []
    reconnect_errors = []
    reconnected = Queue.new
    nc.on_error { |e| errors << e }
    nc.on_reconnect_error { |e| reconnect_errors << e }
    nc.on_reconnect { reconnected << NATS::MonotonicTime.now }
    nc.connect(servers: urls, dont_randomize_servers: true, reconnect_time_wait: 0.1, **opts)
    nc.flush
    [nc, errors, reconnect_errors, reconnected]
  end

  def port_of(nc)
    nc.connected_server.port
  end

  it "reconnects to the server it chooses, like ReconnectToServerCB of nats.go" do
    calls = []
    nc, errors, reconnect_errors, reconnected = connect(reconnect_to_server: ->(pool, info) {
      calls << [pool.map { |srv| srv[:uri].port }, info[:port]]
      [pool.find { |srv| srv[:uri].port == 4923 }, 0]
    })
    expect(port_of(nc)).to eq(4921)

    @servers[0].kill_server
    reconnected.pop(timeout: 5)
    expect(port_of(nc)).to eq(4923)
    expect(calls.first).to eq([[4922, 4923, 4921], 4921])
    expect(errors.grep(NATS::IO::ServerNotInPool)).to be_empty
    expect(reconnect_errors).to be_empty
    nc.close
  end

  it "takes the URL of the server, and waits for as long as it says" do
    disconnected_at = nil
    nc, _, _, reconnected = connect(reconnect_to_server: ->(_pool, _info) { ["127.0.0.1:4923", 0.5] })
    nc.on_disconnect { disconnected_at ||= NATS::MonotonicTime.now }

    @servers[0].kill_server
    reconnected_at = reconnected.pop(timeout: 5)
    expect(port_of(nc)).to eq(4923)
    expect(reconnected_at - disconnected_at).to be >= 0.5
    nc.close
  end

  it "reports ServerNotInPool for a server not in the pool, and picks the next one itself" do
    nc, errors, reconnect_errors, reconnected = connect(reconnect_to_server: ->(_pool, _info) { ["nats://127.0.0.1:4999", 0] })

    @servers[0].kill_server
    reconnected.pop(timeout: 5)
    expect(port_of(nc)).to eq(4922)
    expect(reconnect_errors.first).to be_a(NATS::IO::ServerNotInPool)
    expect(reconnect_errors.first.message).to eq("nats: selected server is not in the pool")
    expect(errors.grep(NATS::IO::ServerNotInPool)).not_to be_empty
    nc.close
  end

  it "leaves the choice to the client when it returns nil" do
    nc, errors, reconnect_errors, reconnected = connect(reconnect_to_server: ->(_pool, _info) {})

    @servers[0].kill_server
    reconnected.pop(timeout: 5)
    expect(port_of(nc)).to eq(4922)
    expect(errors.grep(NATS::IO::ServerNotInPool)).to be_empty
    expect(reconnect_errors).to be_empty
    nc.close
  end

  it "must be callable" do
    expect do
      NATS.connect(urls.first, reconnect_to_server: "nope")
    end.to raise_error(ArgumentError, /reconnect_to_server must respond to call/)
  end
end

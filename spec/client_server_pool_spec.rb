# frozen_string_literal: true

describe "Client - set_server_pool" do
  before(:all) do
    @s1 = NatsServerControl.new("nats://127.0.0.1:4861", "/tmp/test-nats-pool-1.pid")
    @s2 = NatsServerControl.new("nats://127.0.0.1:4862", "/tmp/test-nats-pool-2.pid")
    @s3 = NatsServerControl.new("nats://127.0.0.1:4863", "/tmp/test-nats-pool-3.pid")
  end

  before do
    [@s1, @s2, @s3].each { |s| s.start_server(true) }
  end

  after do
    [@s1, @s2, @s3].each(&:kill_server)
  end

  def pool_urls(nc)
    nc.server_pool.map { |srv| "#{srv[:uri].host}:#{srv[:uri].port}" }
  end

  it "should reconnect to a server of the new pool" do
    reconnected = Queue.new
    nc = NATS.connect(@s1.uri, reconnect_time_wait: 0.1, max_reconnect_attempts: 10)
    nc.on_reconnect { reconnected << true }
    nc.on_error {}
    expect(nc.connected_server.port).to eql(4861)

    nc.set_server_pool([@s2.uri.to_s, @s3.uri.to_s])
    expect(pool_urls(nc)).to contain_exactly("127.0.0.1:4862", "127.0.0.1:4863")
    # Still connected to the server that left the pool.
    expect(nc.connected_server.port).to eql(4861)

    @s1.kill_server
    Timeout.timeout(5) { reconnected.pop }
    expect([4862, 4863]).to include(nc.connected_server.port)

    nc.close
  end

  it "should keep the current server and its state, last in the pool" do
    nc = NATS.connect(@s1.uri, reconnect_time_wait: 0.1, dont_randomize_servers: true)

    nc.set_server_pool(["nats://127.0.0.1:4861", "127.0.0.1:4862"])
    expect(pool_urls(nc)).to eql(["127.0.0.1:4862", "127.0.0.1:4861"])
    expect(nc.server_pool.last[:was_connected]).to be(true)
    expect(nc.server_pool.first[:was_connected]).to be_nil

    # The next reconnect goes to the first one.
    reconnected = Queue.new
    nc.on_reconnect { reconnected << true }
    nc.force_reconnect
    Timeout.timeout(5) { reconnected.pop }
    expect(nc.connected_server.port).to eql(4862)
    expect(pool_urls(nc)).to eql(["127.0.0.1:4861", "127.0.0.1:4862"])

    nc.close
  end

  it "should take URLs like connect does" do
    nc = NATS.connect(@s1.uri)

    nc.set_server_pool(["127.0.0.1:4862", "nats://localhost", URI("nats://127.0.0.1:4863"), "nats://a:4222, nats://b:4223"])
    uris = nc.server_pool.map { |srv| srv[:uri].to_s }
    expect(uris).to contain_exactly("nats://127.0.0.1:4862", "nats://localhost:4222", "nats://127.0.0.1:4863",
      "nats://a:4222", "nats://b:4223")
    expect(nc.discovered_servers).to be_empty

    nc.close
  end

  it "should leave the pool as it was for invalid URLs" do
    nc = NATS.connect(@s1.uri)
    before = pool_urls(nc)

    [
      ["nats://127.0.0.1:4862", "invalid://bad url with spaces"],
      ["nats://127.0.0.1:4862", "nats://"],
      ["http://127.0.0.1:4862"],
      ["nats://127.0.0.1:99999999"]
    ].each do |urls|
      expect { nc.set_server_pool(urls) }.to raise_error(ArgumentError, /invalid server URL/)
    end

    # Like nats.go, websocket and other URLs do not mix.
    expect {
      nc.set_server_pool(["ws://127.0.0.1:8080"])
    }.to raise_error(ArgumentError, /mixing of websocket and non websocket URLs/)
    expect {
      nc.set_server_pool(["nats://127.0.0.1:4862", "wss://127.0.0.1:8080"])
    }.to raise_error(ArgumentError, /mixing/)

    expect(pool_urls(nc)).to eql(before)
    nc.close
  end

  it "should raise ConnectionClosedError once closed" do
    nc = NATS.connect(@s1.uri)
    nc.close

    expect { nc.set_server_pool([@s2.uri.to_s]) }.to raise_error(NATS::IO::ConnectionClosedError)
  end
end

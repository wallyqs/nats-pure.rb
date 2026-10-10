# frozen_string_literal: true

describe "Client#connected? while draining" do
  before(:all) do
    @s = NatsServerControl.new("nats://127.0.0.1:4873", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
  end

  it "should be connected until the drain closes the connection" do
    nc = NATS.connect(@s.uri, drain_timeout: 5)
    closed = Queue.new
    nc.on_close { closed << true }

    gate = Queue.new
    processed = []
    nc.subscribe("draining") do |msg|
      gate.pop
      processed << msg.data
    end
    nc.publish("draining", "a")
    nc.flush

    nc.drain
    wait_until(timeout: 2) { nc.status == NATS::IO::DRAINING_SUBS }

    # Like IsConnected of nats.go.
    expect(nc.draining?).to be(true)
    expect(nc.connected?).to be(true)
    expect(nc.closed?).to be(false)
    expect(nc.connected_server.port).to eql(4873)
    expect(nc.rtt).to be > 0

    gate << true
    Timeout.timeout(5) { closed.pop }
    expect(processed).to eql(["a"])
    expect(nc.connected?).to be(false)
    expect(nc.closed?).to be(true)
  end

  it "should not reconnect when the connection fails while draining" do
    s = NatsServerControl.new("nats://127.0.0.1:4874", "/tmp/test-nats.pid")
    s.start_server(true)

    nc = NATS.connect(s.uri, drain_timeout: 5, reconnect_time_wait: 0.1)
    nc.on_error {}
    closed = Queue.new
    reconnected = false
    nc.on_close { closed << true }
    nc.on_reconnect { reconnected = true }

    nc.subscribe("draining") { sleep 0.5 }
    nc.publish("draining")
    nc.flush
    nc.drain
    wait_until(timeout: 2) { nc.status == NATS::IO::DRAINING_SUBS }

    s.kill_server
    Timeout.timeout(5) { closed.pop }
    expect(nc.closed?).to be(true)
    expect(reconnected).to be(false)
  ensure
    s&.kill_server
  end
end

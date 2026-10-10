# frozen_string_literal: true

describe "Client - RTT" do
  before do
    @s = NatsServerControl.new("nats://127.0.0.1:4860", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after do
    @s.kill_server
  end

  it "should measure the round trip time to the server" do
    nc = NATS.connect(@s.uri)

    rtt = nc.rtt
    expect(rtt).to be_a(Float)
    expect(rtt).to be > 0
    expect(rtt).to be < 1

    # Pending publishes go out before the PING, like with flush.
    msgs = []
    nc.subscribe("rtt") { |msg| msgs << msg }
    10.times { nc.publish("rtt", "hi") }
    nc.rtt
    wait_until(timeout: 2) { msgs.size == 10 }

    nc.close
  end

  it "should raise ConnectionClosedError once the connection is closed" do
    nc = NATS.connect(@s.uri)
    nc.close

    expect { nc.rtt }.to raise_error(NATS::IO::ConnectionClosedError)
  end

  it "should raise Disconnected while reconnecting" do
    nc = NATS.connect(@s.uri, reconnect_time_wait: 10, max_reconnect_attempts: -1)
    nc.on_error {}
    expect(nc.rtt).to be > 0

    @s.kill_server
    wait_until(timeout: 5) { nc.reconnecting? }

    expect { nc.rtt }.to raise_error(NATS::IO::Disconnected)
    expect(NATS::IO::Disconnected.ancestors).to include(NATS::IO::ClientError)

    nc.close
  end
end

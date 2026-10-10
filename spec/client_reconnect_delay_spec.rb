# frozen_string_literal: true

describe "Client - reconnect delay" do
  before do
    @s = NatsServerControl.new("nats://127.0.0.1:4880", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after do
    @s.kill_server
  end

  it "should use reconnect_jitter by default" do
    nc = NATS.connect(@s.uri)
    expect(nc.options[:reconnect_jitter]).to eql(0.1)
    expect(nc.options[:reconnect_jitter_tls]).to eql(1)
    nc.close
  end

  it "should add a random jitter of up to reconnect_jitter to reconnect_time_wait" do
    attempts = []
    nc = NATS::IO::Client.new
    nc.on_error { |e| attempts << NATS::MonotonicTime.now if e.is_a?(Errno::ECONNREFUSED) }
    nc.connect(servers: [@s.uri], reconnect_time_wait: 0.1, reconnect_jitter: 0.4, max_reconnect_attempts: -1)

    @s.kill_server
    wait_until(timeout: 10) { attempts.size >= 6 }
    nc.close

    gaps = attempts.each_cons(2).map { |a, b| b - a }
    expect(gaps).to all(be >= 0.1)
    expect(gaps).to all(be < 0.5 + 0.2)
    # Without the jitter every gap would be close to reconnect_time_wait.
    expect(gaps.max).to be > 0.15
  end

  it "should use reconnect_jitter_tls for TLS connections" do
    nc = NATS::IO::Client.new
    nc.connect(servers: [@s.uri], reconnect_time_wait: 0.5, reconnect_jitter: 0, reconnect_jitter_tls: 2)
    srv = {uri: URI("nats://127.0.0.1:4880"), reconnect_attempts: 1}
    10.times { expect(nc.send(:reconnect_delay, srv)).to eql(0.5) }

    tls_srv = {uri: URI("tls://127.0.0.1:4880"), reconnect_attempts: 1}
    delays = Array.new(20) { nc.send(:reconnect_delay, tls_srv) }
    expect(delays).to all(be >= 0.5)
    expect(delays).to all(be < 2.5)
    expect(delays.uniq.size).to be > 1
    nc.close
  end

  it "should wait what custom_reconnect_delay returns for the attempts so far" do
    calls = []
    reconnected = false
    nc = NATS::IO::Client.new
    nc.on_reconnect { reconnected = true }
    nc.connect(servers: [@s.uri], reconnect_time_wait: 10, max_reconnect_attempts: -1,
      custom_reconnect_delay: proc { |attempts|
        calls << [attempts, NATS::MonotonicTime.now]
        0.2
      })

    @s.kill_server
    wait_until(timeout: 5) { calls.size >= 3 }
    expect(calls.map(&:first).first(3)).to eql([1, 2, 3])
    calls.each_cons(2).first(2).each do |(_, a), (_, b)|
      expect(b - a).to be_between(0.2, 0.2 + 0.5)
    end

    # reconnect_time_wait of 10 seconds is not used.
    @s.start_server(true)
    wait_until(timeout: 5) { reconnected }
    nc.close
  end

  it "should reject invalid reconnect delay options" do
    expect do
      NATS::IO::Client.new(@s.uri, custom_reconnect_delay: 1)
    end.to raise_error(ArgumentError, /custom_reconnect_delay/)

    expect do
      NATS::IO::Client.new(@s.uri, reconnect_jitter: -1)
    end.to raise_error(ArgumentError, /reconnect_jitter/)

    expect do
      NATS::IO::Client.new(@s.uri, reconnect_jitter_tls: "1")
    end.to raise_error(ArgumentError, /reconnect_jitter_tls/)
  end
end

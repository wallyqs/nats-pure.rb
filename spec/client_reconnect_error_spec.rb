# frozen_string_literal: true

describe "Client - on_reconnect_error" do
  let(:port) { 4808 }
  let(:url) { "nats://127.0.0.1:#{port}" }

  before do
    @server = NatsServerControl.new(url, "/tmp/test-nats-reconnect-error.pid", "-a 127.0.0.1")
  end

  after do
    @server.kill_server
  end

  it "is called with the error of each failed attempt to reconnect, like nats.go" do
    @server.start_server(true)
    nc = NATS::IO::Client.new
    reconnect_errors = Queue.new
    errors = Queue.new
    reconnected = Queue.new
    handler = nc.on_reconnect_error { |e| reconnect_errors << e }
    nc.on_error { |e| errors << e }
    nc.on_reconnect { reconnected << true }
    nc.connect(url, reconnect_time_wait: 0.1, max_reconnect_attempts: -1)
    expect(nc.reconnect_error_handler).to be(handler)

    @server.kill_server
    Timeout.timeout(5) { sleep 0.05 until reconnect_errors.size >= 3 }
    expect(reconnect_errors.pop).to be_a(Errno::ECONNREFUSED)

    @server.start_server(true)
    Timeout.timeout(5) { reconnected.pop }
    reconnect_errors.clear
    nc.flush
    expect(reconnect_errors).to be_empty

    # They still go to on_error too, as before.
    expect(errors.size).to be >= 3
    nc.close
  end

  it "reports the failed first connect and its retries with retry_on_failed_connect" do
    nc = NATS::IO::Client.new
    reconnect_errors = Queue.new
    connected = Queue.new
    nc.on_reconnect_error { |e| reconnect_errors << e }
    nc.on_connect { connected << true }
    nc.connect(url, retry_on_failed_connect: true, reconnect_time_wait: 0.1, max_reconnect_attempts: -1)

    Timeout.timeout(5) { sleep 0.05 until reconnect_errors.size >= 2 }
    expect(reconnect_errors.pop).to be_a(Errno::ECONNREFUSED)

    @server.start_server(true)
    Timeout.timeout(5) { connected.pop }
    nc.close
  end

  it "hands what it raises to on_error and goes on reconnecting" do
    @server.start_server(true)
    nc = NATS::IO::Client.new
    errors = Queue.new
    reconnected = Queue.new
    nc.on_reconnect_error { |_e| raise "oops" }
    nc.on_error { |e| errors << e }
    nc.on_reconnect { reconnected << true }
    nc.connect(url, reconnect_time_wait: 0.1, max_reconnect_attempts: -1)

    @server.kill_server
    Timeout.timeout(5) do
      sleep 0.05 until errors.size >= 2
    end
    expect(Array.new(errors.size) { errors.pop }.map(&:message)).to include("oops")

    @server.start_server(true)
    Timeout.timeout(5) { reconnected.pop }
    expect(nc.connected?).to be(true)
    nc.close
  end
end

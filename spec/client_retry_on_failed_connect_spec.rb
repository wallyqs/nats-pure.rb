# frozen_string_literal: true

describe "Client - retry_on_failed_connect" do
  let(:port) { 4806 }
  let(:url) { "nats://127.0.0.1:#{port}" }

  before do
    @server = NatsServerControl.new(url, "/tmp/test-nats-retry-connect.pid", "-a 127.0.0.1")
  end

  after do
    @server.kill_server
  end

  def new_client
    nc = NATS::IO::Client.new
    events = Queue.new
    nc.on_connect { events << :connect }
    nc.on_reconnect { events << :reconnect }
    nc.on_disconnect { events << :disconnect }
    nc.on_close { events << :close }
    [nc, events]
  end

  it "returns at once and connects in the background, like nats.go" do
    nc, events = new_client
    started = NATS::MonotonicTime.now
    nc.connect(url, retry_on_failed_connect: true, reconnect_time_wait: 0.2, max_reconnect_attempts: -1)
    expect(NATS::MonotonicTime.since(started)).to be < 0.5
    expect(nc.reconnecting?).to be(true)

    # What is subscribed and published meanwhile goes out once connected.
    msgs = Queue.new
    nc.subscribe("retry") { |msg| msgs << msg.data }
    nc.publish("retry", "buffered")

    sleep 0.5
    expect(events).to be_empty

    @server.start_server(true)
    expect(Timeout.timeout(5) { events.pop }).to eq(:connect)
    expect(nc.connected?).to be(true)
    expect(Timeout.timeout(5) { msgs.pop }).to eq("buffered")

    nc.publish("retry", "connected")
    expect(Timeout.timeout(5) { msgs.pop }).to eq("connected")
    expect(nc.stats[:reconnects]).to eq(0)
    expect(events).to be_empty

    # Later reconnects are reported as such.
    nc.force_reconnect
    expect(Timeout.timeout(5) { events.pop }).to eq(:disconnect)
    expect(Timeout.timeout(5) { events.pop }).to eq(:reconnect)
    nc.close
  end

  it "closes the connection once out of attempts" do
    nc, events = new_client
    errors = Queue.new
    nc.on_error { |e| errors << e }
    nc.connect(url, retry_on_failed_connect: true, reconnect_time_wait: 0.1, max_reconnect_attempts: 3)
    expect(nc.reconnecting?).to be(true)

    Timeout.timeout(5) { sleep 0.05 until nc.closed? }
    expect(events.pop(true)).to eq(:disconnect)
    expect(events.pop(true)).to eq(:close)
    expect(nc.last_error).to be_a(NATS::IO::NoServersError)
    expect(errors.size).to be >= 3
    expect(errors.pop).to be_a(Errno::ECONNREFUSED)
  end

  it "stops trying once closed" do
    nc, events = new_client
    nc.connect(url, retry_on_failed_connect: true, reconnect_time_wait: 0.1, max_reconnect_attempts: -1)
    nc.close
    expect(nc.closed?).to be(true)

    @server.start_server(true)
    sleep 0.5
    expect(nc.closed?).to be(true)
    expect(events.size).to eq(2) # :disconnect and :close from close
    expect(events.pop(true)).to eq(:disconnect)
    expect(events.pop(true)).to eq(:close)
  end

  it "connects right away when it can" do
    @server.start_server(true)
    nc, events = new_client
    nc.connect(url, retry_on_failed_connect: true)
    expect(nc.connected?).to be(true)
    expect(events.pop(true)).to eq(:connect)
    nc.close
  end

  it "blocks retrying by default, as before" do
    nc, = new_client
    started = NATS::MonotonicTime.now
    expect do
      nc.connect(url, reconnect_time_wait: 0.2, max_reconnect_attempts: 2)
    end.to raise_error(Errno::ECONNREFUSED)
    expect(NATS::MonotonicTime.since(started)).to be >= 0.4
  end
end

# frozen_string_literal: true

describe "Client - no_callbacks_after_client_close" do
  before(:all) do
    @port = 4810
    @server = NatsServerControl.new("nats://127.0.0.1:#{@port}", "/tmp/test-nats-no-callbacks.pid", "-a 127.0.0.1")
    @server.start_server(true)
  end

  after(:all) { @server.kill_server }

  let(:url) { "nats://127.0.0.1:#{@port}" }

  def connect(**opts)
    nc = NATS::IO::Client.new
    events = Queue.new
    nc.on_disconnect { events << :disconnect }
    nc.on_close { events << :close }
    nc.on_error { |e| events << e }
    nc.connect(url, **opts)
    [nc, events]
  end

  it "calls on_disconnect and on_close on close by default" do
    nc, events = connect
    nc.close
    expect(Array.new(events.size) { events.pop }).to eq([:disconnect, :close])
  end

  it "calls neither on close with the option, like nats.go" do
    nc, events = connect(no_callbacks_after_client_close: true)
    sub_closed = Queue.new
    sub = nc.subscribe("foo") { |_msg| }
    sub.on_close { |subject| sub_closed << subject }

    nc.close
    expect(nc.closed?).to be(true)
    sleep 0.2
    expect(events).to be_empty
    # Subscriptions are still told, as in nats.go.
    expect(Timeout.timeout(2) { sub_closed.pop }).to eq("foo")
  end

  it "still calls them when the client closes the connection itself" do
    nc, events = connect(no_callbacks_after_client_close: true)
    nc.subscribe("foo") { |_msg| }
    nc.drain
    Timeout.timeout(5) { sleep 0.05 until nc.closed? }
    expect(Array.new(events.size) { events.pop }).to eq([:disconnect, :close])
  end

  it "still calls them when the client gives up reconnecting" do
    server = NatsServerControl.new("nats://127.0.0.1:4811", "/tmp/test-nats-no-callbacks-2.pid", "-a 127.0.0.1")
    server.start_server(true)
    nc = NATS::IO::Client.new
    events = Queue.new
    nc.on_close { events << :close }
    nc.connect("nats://127.0.0.1:4811", no_callbacks_after_client_close: true, reconnect_time_wait: 0.1, max_reconnect_attempts: 1)

    server.kill_server
    expect(Timeout.timeout(5) { events.pop }).to eq(:close)
  ensure
    server&.kill_server
  end
end

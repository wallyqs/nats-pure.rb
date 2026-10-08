# frozen_string_literal: true

describe "Client - reconnect buffer" do
  before do
    @s = NatsServerControl.new("nats://127.0.0.1:4890", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after do
    @s.kill_server
  end

  def connect_and_disconnect(**opts)
    disconnected = false
    reconnected = false
    nc = NATS::IO::Client.new
    nc.on_disconnect { disconnected = true }
    nc.on_reconnect { reconnected = true }
    nc.connect({servers: [@s.uri], reconnect_time_wait: 0.2, max_reconnect_attempts: -1}.merge(opts))
    nc.flush

    @s.kill_server
    wait_until(timeout: 5) { disconnected && nc.reconnecting? }

    [nc, -> { reconnected }]
  end

  it "should buffer up to 8 MiB by default" do
    nc, = connect_and_disconnect
    expect(nc.options[:reconnect_buf_size]).to eql(8 * 1024 * 1024)

    # 1 MiB a message, each checked against what was buffered before it:
    # the eighth still fits, the ninth goes over.
    payload = "a" * 1024 * 1024
    8.times { nc.publish("buf.default", payload) }
    expect { nc.publish("buf.default", payload) }.to raise_error(NATS::IO::ReconnectBufExceeded)
    nc.close
  end

  it "should raise ReconnectBufExceeded once reconnect_buf_size bytes are buffered" do
    msgs = []
    nc, reconnected = connect_and_disconnect(reconnect_buf_size: 32)
    nc.subscribe("foo") { |msg| msgs << msg.data }

    # "PUB foo  4\r\nfood\r\n" is 18 bytes: two fit, a third would go over,
    # like in nats.go.
    nc.publish("foo", "food")
    nc.publish("foo", "food")
    expect { nc.publish("foo", "food") }.to raise_error(NATS::IO::ReconnectBufExceeded, /outbound buffer limit exceeded/)
    expect do
      nc.publish_msg(NATS::Msg.new(subject: "foo", data: "food", header: {"a" => "b"}))
    end.to raise_error(NATS::IO::ReconnectBufExceeded)
    # A client error, so that generic rescue clauses still catch it.
    expect(NATS::IO::ReconnectBufExceeded.ancestors).to include(NATS::IO::ClientError, NATS::IO::Error)

    # Once reconnected, the subscription is replayed and the two buffered
    # messages are sent; the connection gets them back.
    @s.start_server(true)
    wait_until(timeout: 5) { reconnected.call }
    nc.flush
    wait_until(timeout: 5) { msgs.size >= 2 }
    sleep 0.1
    expect(msgs).to eql(%w[food food])

    # And the buffer limit no longer applies.
    3.times { nc.publish("foo", "more") }
    nc.flush
    nc.close
  end

  it "should not buffer at all with a negative reconnect_buf_size" do
    nc, reconnected = connect_and_disconnect(reconnect_buf_size: -1)

    expect { nc.publish("foo", "food") }.to raise_error(NATS::IO::ReconnectBufExceeded)

    @s.start_server(true)
    wait_until(timeout: 5) { reconnected.call }
    expect { nc.publish("foo", "food") }.not_to raise_error
    nc.flush
    nc.close
  end

  it "should reject a reconnect_buf_size that is not an Integer" do
    expect do
      NATS::IO::Client.new(@s.uri, reconnect_buf_size: "1024")
    end.to raise_error(ArgumentError, /reconnect_buf_size/)
  end
end

# frozen_string_literal: true

describe "Client - reconnect_on_flusher_error" do
  before do
    @server = NatsServerControl.new("nats://127.0.0.1:4925", "/tmp/test-nats-flusher-error.pid", "-a 127.0.0.1")
    @server.start_server(true)
  end

  after do
    begin
      Process.kill("CONT", @server.server_pid)
    rescue Errno::ESRCH
    end
    @server.kill_server
  end

  let(:payload) { "x" * 128 * 1024 }

  # Stops the server from reading, so that the socket buffers fill up and
  # the writes of the flusher time out, then publishes until one does.
  def publish_until_write_error(nc, errors)
    Process.kill("STOP", @server.server_pid)
    400.times do
      break unless errors.empty?

      nc.publish("stalled", payload)
      sleep 0.01
    end
    Timeout.timeout(10) { errors.pop }
  end

  def connect(**opts)
    errors = Queue.new
    disconnected = Queue.new
    nc = NATS.connect("nats://127.0.0.1:4925", flusher_timeout: 0.3, reconnect_time_wait: 0.2, **opts)
    nc.on_error { |e| errors << e }
    nc.on_disconnect { disconnected << true }
    [nc, errors, disconnected]
  end

  it "reconnects on a write error by default, as before" do
    nc, errors, disconnected = connect
    expect(publish_until_write_error(nc, errors)).to be_a(NATS::IO::SocketTimeoutError)
    Timeout.timeout(10) { disconnected.pop }
    nc.close
  end

  it "only reports a write error when false, like ReconnectOnFlusherError of nats.go" do
    nc, errors, disconnected = connect(reconnect_on_flusher_error: false)
    expect(publish_until_write_error(nc, errors)).to be_a(NATS::IO::SocketTimeoutError)
    expect(nc.last_error).to be_a(NATS::IO::SocketTimeoutError)

    sleep 0.5
    expect(disconnected).to be_empty
    expect(nc).to be_connected
    expect(nc.stats[:reconnects]).to eq(0)
    nc.close
  end
end

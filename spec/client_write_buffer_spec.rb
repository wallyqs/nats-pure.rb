# frozen_string_literal: true

describe "Client - write_buffer_size and flusher_timeout" do
  before do
    @port = 4802
    @server = NatsServerControl.new("nats://127.0.0.1:#{@port}", "/tmp/test-nats-write-buffer.pid", "-a 127.0.0.1")
    @server.start_server(true)
  end

  after do
    begin
      Process.kill("CONT", @server.server_pid)
    rescue Errno::ESRCH
    end
    @server.kill_server
  end

  let(:url) { "nats://127.0.0.1:#{@port}" }
  let(:payload) { "x" * 128 * 1024 }

  # Stops the server from reading, as a server that hangs does, so that
  # the socket buffers fill up and writes block.
  def stall_server
    Process.kill("STOP", @server.server_pid)
  end

  def resume_server
    Process.kill("CONT", @server.server_pid)
  end

  # Publishes until the connection is lost, returning how long the
  # slowest publish took.
  def publish_until_disconnected(nc, disconnected)
    slowest = 0
    400.times do
      break unless disconnected.empty?

      started = NATS::MonotonicTime.now
      begin
        nc.publish("stalled", payload)
      rescue NATS::IO::ReconnectBufExceeded
        sleep 0.05
      end
      slowest = [slowest, NATS::MonotonicTime.since(started)].max
    end
    slowest
  end

  it "keeps the messages in order when publishers write them out" do
    received = []
    done = Queue.new
    sub_nc = NATS.connect(url)
    sub_nc.subscribe("ordered") do |msg|
      received << msg.data.to_i
      done << true if received.size == 5000
    end
    sub_nc.flush

    nc = NATS.connect(url, write_buffer_size: 256)
    5000.times { |i| nc.publish("ordered", i.to_s) }
    nc.flush
    Timeout.timeout(10) { done.pop }
    expect(received).to eq((0...5000).to_a)

    nc.close
    sub_nc.close
  end

  it "has the publisher write out what is pending once write_buffer_size bytes are" do
    nc = NATS.connect(url, write_buffer_size: 4096)
    writes = []
    io = nc.instance_variable_get(:@io)
    allow(io).to receive(:write).and_wrap_original do |m, data, *args|
      writes << [Thread.current, data.bytesize]
      m.call(data, *args)
    end

    # Under the limit, the flusher thread writes.
    nc.publish("small", "a")
    nc.flush
    expect(writes.map(&:first)).not_to include(Thread.current)

    # Over it, the publish writes.
    writes.clear
    nc.publish("big", "x" * 5000)
    expect(writes.first).to eq([Thread.current, "PUB big  5000\r\n".bytesize + 5002])
    expect(nc.buffered).to eq(0)
    nc.close
  end

  it "fails the connection, and reconnects, once a write blocks for flusher_timeout" do
    errors = Queue.new
    disconnected = Queue.new
    reconnected = Queue.new
    nc = NATS.connect(url, flusher_timeout: 0.5, reconnect_time_wait: 0.2, max_reconnect_attempts: -1)
    nc.on_error { |e| errors << e }
    nc.on_disconnect { disconnected << true }
    nc.on_reconnect { reconnected << true }

    stall_server
    started = NATS::MonotonicTime.now
    # Publishes do not block: the flusher thread is the one that waits.
    expect(publish_until_disconnected(nc, disconnected)).to be < 0.5
    error = Timeout.timeout(10) { errors.pop }
    expect(error).to be_a(NATS::IO::SocketTimeoutError)
    expect(error.message).to match(/timeout writing/)
    expect(NATS::MonotonicTime.since(started)).to be >= 0.5
    Timeout.timeout(10) { disconnected.pop }

    resume_server
    Timeout.timeout(10) { reconnected.pop }
    expect(nc.connected?).to be(true)
    nc.close
  end

  it "makes the publisher wait up to flusher_timeout with write_buffer_size" do
    errors = Queue.new
    disconnected = Queue.new
    nc = NATS.connect(url, write_buffer_size: 32 * 1024, flusher_timeout: 0.5, reconnect_time_wait: 0.2, max_reconnect_attempts: -1)
    nc.on_error { |e| errors << e }
    nc.on_disconnect { disconnected << true }

    stall_server
    # The publish that finds the socket full waits for it, as in nats.go.
    expect(publish_until_disconnected(nc, disconnected)).to be >= 0.4
    expect(Timeout.timeout(10) { errors.pop }).to be_a(NATS::IO::SocketTimeoutError)

    resume_server
    nc.close
  end

  it "refuses values that are not positive" do
    expect { NATS.connect(url, write_buffer_size: 0) }.to raise_error(ArgumentError, /write_buffer_size/)
    expect { NATS.connect(url, flusher_timeout: -1) }.to raise_error(ArgumentError, /flusher_timeout/)
  end
end

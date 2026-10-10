# frozen_string_literal: true

require "tmpdir"

describe "JetStream async publish - connection lost or closed" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-publish-async-conn")
    @s = NatsServerControl.new("nats://127.0.0.1:4876", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  # A subscriber that takes the messages on a subject without acking them,
  # so that their publishes await acks.
  def silent_subscriber(nc, subject)
    nc.subscribe(subject) {}
    nc.flush
  end

  it "fails the futures that await acks with ConnectionClosedError on close" do
    nc = NATS.connect(@s.uri)
    closed = Queue.new
    nc.on_close { closed << true }
    failed = Queue.new
    js = nc.jetstream(publish_async_err_handler: ->(msg, err) { failed << [msg.subject, err] })
    silent_subscriber(nc, "silent")

    futures = 3.times.map { js.publish_async("silent", "hi") }
    nc.flush
    expect(js.publish_async_pending).to eql(3)
    expect(futures.map(&:done?)).to eql([false, false, false])

    nc.close
    # The callback of the user still runs.
    expect(Timeout.timeout(2) { closed.pop }).to be(true)

    expect(futures.map(&:done?)).to eql([true, true, true])
    expect(futures.map(&:err)).to all(be_a(NATS::IO::ConnectionClosedError))
    expect { futures.first.wait(1) }.to raise_error(NATS::IO::ConnectionClosedError)
    expect(js.publish_async_pending).to eql(0)
    js.publish_async_complete(timeout: 1)
    expect(3.times.map { failed.pop }.map(&:first)).to eql(%w[silent silent silent])
  end

  it "fails them with Disconnected when the connection is lost, and goes on after the reconnect" do
    nc = NATS.connect(@s.uri, reconnect_time_wait: 0.2, max_reconnect_attempts: -1)
    nc.on_error {}
    disconnected = Queue.new
    reconnected = Queue.new
    nc.on_disconnect { disconnected << true }
    nc.on_reconnect { reconnected << true }
    js = nc.jetstream
    silent_subscriber(nc, "silent")

    future = js.publish_async("silent", "hi")
    nc.flush
    expect(future.done?).to be(false)

    @s.kill_server
    Timeout.timeout(5) { disconnected.pop }
    wait_until(timeout: 5) { future.done? }
    expect(future.err).to be_a(NATS::IO::Disconnected)
    expect(js.publish_async_pending).to eql(0)

    @s.start_server(true)
    Timeout.timeout(10) { reconnected.pop }
    nc.jsm.add_stream(name: "AFTER", subjects: ["after"])
    ack = js.publish_async("after", "hi").wait(5)
    expect(ack.stream).to eql("AFTER")
    expect(ack.seq).to eql(1)

    nc.close
  end

  it "subscribes to the acks again on a new connection after a close" do
    nc = NATS.connect(@s.uri)
    js = nc.jetstream
    nc.jsm.add_stream(name: "AGAIN", subjects: ["again"])
    expect(js.publish_async("again", "1").wait(5).seq).to eql(1)

    nc.close
    nc.connect(@s.uri)
    expect(js.publish_async("again", "2").wait(5).seq).to eql(2)
    nc.close
  end
end

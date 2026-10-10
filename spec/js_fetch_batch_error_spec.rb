# frozen_string_literal: true

describe "JetStream fetch MessageBatch" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-fetch-batch-error")
    @s = NatsServerControl.new("nats://127.0.0.1:4734", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri, max_reconnect_attempts: -1, reconnect_time_wait: 0.2) }
  let(:js) { nc.jetstream }
  let(:sub) { js.pull_subscribe("mb.>", "c1", stream: "MB") }

  before do
    js.add_stream(name: "MB", subjects: ["mb.>"])
    js.add_consumer("MB", durable_name: "c1", ack_policy: "explicit")
    sub
    nc.flush
  end

  after { nc.close }

  # Stops the server, which keeps the connection but sends nothing more,
  # until the block returns.
  def server_stopped
    pid = @s.server_pid
    Process.kill("STOP", pid)
    yield
  ensure
    Process.kill("CONT", pid)
  end

  def fetching(batch, params)
    fetch = Thread.new { sub.fetch(batch, params) }
    js.publish("mb.a", "1")
    eventually { expect(js.consumer_info("MB", "c1").num_ack_pending).to eql(1) }
    fetch
  end

  it "is an Array of the messages, without error when the fetch got its batch" do
    2.times { |i| js.publish("mb.a", i.to_s) }
    msgs = sub.fetch(2, timeout: 1)

    expect(msgs).to be_a(NATS::JetStream::MessageBatch)
    expect(msgs).to be_a(Array)
    expect(msgs.map(&:data)).to eql(%w[0 1])
    expect(msgs.error).to be_nil
  end

  it "has no error when the pull expired, or ran out of messages, after some came" do
    js.publish("mb.a", "1")
    msgs = sub.fetch(5, timeout: 0.5)
    expect(msgs.map(&:data)).to eql(["1"])
    expect(msgs.error).to be_nil

    js.publish("mb.a", "2")
    msgs = sub.fetch(5, no_wait: true)
    expect(msgs.map(&:data)).to eql(["2"])
    expect(msgs.error).to be_nil
  end

  it "has no error when the next message would exceed max_bytes" do
    js.publish("mb.a", "1")
    js.publish("mb.a", "x" * 1000)
    msgs = sub.fetch(5, timeout: 1, max_bytes: 200)

    expect(msgs.map(&:data)).to eql(["1"])
    expect(msgs.error).to be_nil
  end

  it "has NoHeartbeat as its error when the heartbeats stopped after some messages" do
    fetch = fetching(5, timeout: 5, heartbeat: 0.3)

    msgs = server_stopped { fetch.value }
    expect(msgs.map(&:data)).to eql(["1"])
    expect(msgs.error).to be_a(NATS::JetStream::Error::NoHeartbeat)
  end

  it "has ConsumerDeleted as its error when the consumer was deleted after some messages" do
    fetch = fetching(5, timeout: 5)
    js.delete_consumer("MB", "c1")

    msgs = fetch.value
    expect(msgs.map(&:data)).to eql(["1"])
    expect(msgs.error).to be_a(NATS::JetStream::Error::ConsumerDeleted)
  end

  it "still raises the error when no messages came" do
    fetch = Thread.new do
      sub.fetch(5, timeout: 5)
    rescue => e
      e
    end
    eventually { expect(js.consumer_info("MB", "c1").num_waiting).to eql(1) }
    js.delete_consumer("MB", "c1")

    expect(fetch.value).to be_a(NATS::JetStream::Error::ConsumerDeleted)
  end

  it "is what the fetches of consumer handles and ordered consumers return" do
    js.publish("mb.a", "1")
    msgs = js.consumer("MB", "c1").fetch(1, timeout: 1)
    expect(msgs).to be_a(NATS::JetStream::MessageBatch)
    expect(msgs.error).to be_nil

    msgs = js.stream("MB").ordered_consumer.fetch(1, timeout: 1)
    expect(msgs).to be_a(NATS::JetStream::MessageBatch)
    expect(msgs.map(&:data)).to eql(["1"])
    expect(msgs.error).to be_nil
  end
end

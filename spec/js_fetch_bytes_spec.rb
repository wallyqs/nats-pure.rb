# frozen_string_literal: true

describe "JetStream fetch by bytes" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-fetch-bytes")
    @s = NatsServerControl.new("nats://127.0.0.1:4732", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:sub) { js.pull_subscribe("fb.>", "c1", stream: "FB") }
  let(:pulls) { nc.subscribe("$JS.API.CONSUMER.MSG.NEXT.FB.c1") }

  before do
    js.add_stream(name: "FB", subjects: ["fb.>"])
    js.add_consumer("FB", durable_name: "c1", ack_policy: "explicit")
    sub
    pulls
    nc.flush
  end

  after { nc.close }

  def size_of(msg)
    NATS::JetStream.const_get(:JS).msg_size(msg)
  end

  def timed
    started = NATS::MonotonicTime.now
    [yield, NATS::MonotonicTime.since(started)]
  end

  def pulls_sent
    nc.flush
    Array.new(pulls.pending_queue.size) { JSON.parse(pulls.next_msg.data, symbolize_names: true) }
  end

  # The sizes of the messages as another consumer of the same name length
  # gets them: the same subjects, headers, data and ack reply lengths.
  def sizes(count)
    js.add_consumer("FB", durable_name: "c2", ack_policy: "explicit")
    js.pull_subscribe("fb.>", "c2", stream: "FB").fetch(count, timeout: 1).map { |msg| size_of(msg) }
  end

  it "sends max_bytes with the pull" do
    js.publish("fb.a", "x" * 10)
    sub.fetch(5, max_bytes: 1_000, timeout: 1)

    expect(pulls_sent.first).to include(batch: 5, max_bytes: 1_000)
  end

  it "ends as soon as the next message would exceed max_bytes" do
    5.times { |i| js.publish("fb.a", i.to_s * 100) }
    two = sizes(2).sum

    msgs, elapsed = timed { sub.fetch(10, max_bytes: two + 10, timeout: 5) }
    expect(msgs.map(&:data)).to eql(["0" * 100, "1" * 100])
    expect(elapsed).to be < 1
    # The rest is left for the next fetch.
    expect(sub.fetch(10, max_bytes: 10_000, timeout: 1).map(&:data)).to eql(%w[2 3 4].map { |d| d * 100 })
  end

  it "ends once it has taken exactly max_bytes" do
    js.publish("fb.a", "a" * 50, header: {"Foo" => "bar"})
    js.publish("fb.b", "b" * 70)
    js.publish("fb.c", "c" * 90)
    two = sizes(2).sum

    msgs, elapsed = timed { sub.fetch(10, max_bytes: two, timeout: 5) }
    expect(msgs.map(&:subject)).to eql(%w[fb.a fb.b])
    expect(elapsed).to be < 1
  end

  it "ends with the batch before max_bytes" do
    5.times { |i| js.publish("fb.a", i.to_s) }

    msgs, elapsed = timed { sub.fetch(2, max_bytes: 100_000, timeout: 5) }
    expect(msgs.map(&:data)).to eql(%w[0 1])
    expect(elapsed).to be < 1
    # The 409 Batch Completed that ends the pull does not end the next fetch.
    nc.flush
    expect(sub.fetch(3, timeout: 1).map(&:data)).to eql(%w[2 3 4])
  end

  it "raises MaxBytesExceeded when the first message exceeds max_bytes" do
    js.publish("fb.a", "x" * 500)

    _, elapsed = timed do
      expect { sub.fetch(10, max_bytes: 100, timeout: 5) }.to raise_error(NATS::JetStream::Error::MaxBytesExceeded) { |e|
        expect(e.code).to eql(409)
        expect(e).to be_a(NATS::JetStream::Error::APIError)
      }
    end
    expect(elapsed).to be < 1
    # The message stays for a fetch that takes it.
    expect(sub.fetch(1, max_bytes: 1_000, timeout: 1).map(&:data)).to eql(["x" * 500])
  end

  it "raises MaxBytesExceeded without waiting when it does not wait" do
    js.publish("fb.a", "x" * 500)

    expect { sub.fetch(10, max_bytes: 100, no_wait: true) }.to raise_error(NATS::JetStream::Error::MaxBytesExceeded)
    expect(sub.fetch(1, no_wait: true).map(&:data)).to eql(["x" * 500])
  end

  it "counts the messages that earlier pulls left" do
    3.times { |i| js.publish("fb.a", i.to_s * 100) }
    one = sizes(1).first
    # A fetch broken off by its block leaves the rest of its pull behind.
    sub.fetch(3, timeout: 1) { break }
    wait_until { sub.pending_queue.size == 2 }

    msgs = sub.fetch(10, max_bytes: one + 10, timeout: 1)
    expect(msgs.map(&:data)).to eql(["1" * 100])
    expect(pulls_sent.size).to eql(1)
    # The message that did not fit is held for the next fetch.
    expect(sub.fetch(10, max_bytes: 10_000, timeout: 1).map(&:data)).to eql(["2" * 100])
  end

  it "refuses an invalid max_bytes" do
    [0, -1, 1.5, "10"].each do |max_bytes|
      expect { sub.fetch(1, max_bytes: max_bytes) }.to raise_error(ArgumentError)
    end
  end
end

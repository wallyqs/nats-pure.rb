# frozen_string_literal: true

describe "JetStream continuous pull options" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-consume-opts")
    @s = NatsServerControl.new("nats://127.0.0.1:4765", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:psub) { js.pull_subscribe("opts.>", "c1", stream: "OPTS") }
  let(:pulls) { nc.subscribe("$JS.API.CONSUMER.MSG.NEXT.OPTS.c1") }

  before do
    js.add_stream(name: "OPTS", subjects: ["opts.>"])
    js.add_consumer("OPTS", durable_name: "c1", ack_policy: "explicit")
    psub
    pulls
    nc.flush
  end

  after { nc.close }

  def publish(count, size: 1)
    count.times { |i| js.publish("opts.a", i.to_s.ljust(size, "x")) }
  end

  def pulls_sent
    nc.flush
    Array.new(pulls.pending_queue.size) { JSON.parse(pulls.next_msg.data, symbolize_names: true) }
  end

  describe "stop_after" do
    it "stops consume after that many messages, pulling no more" do
      publish(20)
      got = Queue.new
      cc = psub.consume(max_messages: 5, stop_after: 7) do |msg|
        msg.ack
        got << msg.data
      end

      expect(cc.wait_closed(5)).to be(true)
      expect(Array.new(got.size) { got.pop }).to eql((0...7).map(&:to_s))
      expect(pulls_sent.sum { |pull| pull[:batch] }).to eql(7)
      expect(psub.consumer_info.num_pending).to eql(13)
    end

    it "closes messages after that many messages" do
      publish(5)
      msgs = psub.messages(stop_after: 3)

      expect(msgs.map { |msg| msg.tap(&:ack).data }).to eql(%w[0 1 2])
      expect(msgs).to be_closed
      expect { msgs.next }.to raise_error(NATS::JetStream::Error::MsgIteratorClosed)
      expect(pulls_sent.map { |pull| pull[:batch] }).to eql([3])
    end

    it "asks for no more than are left when it pulls again" do
      msgs = psub.messages(max_messages: 4, stop_after: 6, expires: 1, heartbeat: 0.5)
      publish(6)

      expect(Array.new(6) { msgs.next(timeout: 5).data }).to eql((0...6).map(&:to_s))
      expect(msgs).to be_closed
      # The second pull asks only for the messages left to take.
      expect(pulls_sent.map { |pull| pull[:batch] }).to eql([4, 2])
    end

    it "counts the messages across the consumers of an ordered consumer" do
      publish(6)
      oc = js.ordered_consumer("OPTS")
      msgs = oc.messages(stop_after: 4)

      expect(Array.new(2) { msgs.next(timeout: 2).data }).to eql(%w[0 1])
      # A new consumer, from the next message, takes the rest.
      js.delete_consumer("OPTS", oc.consumer_name)
      expect(Array.new(2) { msgs.next(timeout: 10).data }).to eql(%w[2 3])
      expect(msgs).to be_closed
      expect { msgs.next }.to raise_error(NATS::JetStream::Error::MsgIteratorClosed)
    end

    it "stops an ordered consume after that many messages" do
      publish(6)
      got = Queue.new
      cc = js.ordered_consumer("OPTS").consume(stop_after: 5) { |msg| got << msg.data }

      expect(cc.wait_closed(5)).to be(true)
      expect(Array.new(got.size) { got.pop }).to eql((0...5).map(&:to_s))
    end
  end

  describe "bytes_limit" do
    it "keeps max_messages asked for, with each pull taking at most the bytes" do
      publish(10, size: 100)
      got = Queue.new
      cc = psub.consume(max_messages: 10, bytes_limit: 1024) do |msg|
        msg.ack
        got << msg.data
      end

      expect(Array.new(10) { got.pop(timeout: 5)[0, 1] }).to eql((0...10).map(&:to_s))
      cc.stop
      first, *more = pulls_sent
      expect(first).to eql({batch: 10, max_bytes: 1024, expires: 30_000_000_000, idle_heartbeat: 15_000_000_000})
      # A pull ends at the byte limit, short of its batch, and more follow.
      expect(more).not_to be_empty
      expect(more.map { |pull| pull[:max_bytes] }).to all(eql(1024))
    end

    it "works with messages and stop_after" do
      publish(10, size: 100)
      msgs = psub.messages(max_messages: 8, bytes_limit: 512, stop_after: 6)

      expect(msgs.map { |msg| msg.tap(&:ack).data[0, 1] }).to eql((0...6).map(&:to_s))
      expect(pulls_sent.map { |pull| pull[:max_bytes] }.uniq).to eql([512])
    end
  end

  it "refuses invalid options" do
    [
      {stop_after: 0},
      {stop_after: 1.5},
      {bytes_limit: 0},
      {max_bytes: 1024, bytes_limit: 1024}
    ].each do |opts|
      expect { psub.consume(opts) { |msg| msg } }.to raise_error(ArgumentError)
      expect { psub.messages(opts) }.to raise_error(ArgumentError)
    end
    expect(pulls_sent).to be_empty
  end
end

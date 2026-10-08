# frozen_string_literal: true

describe "JetStream continuous pull consumption" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-consume")
    @s = NatsServerControl.new("nats://127.0.0.1:4734", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri, max_reconnect_attempts: -1, reconnect_time_wait: 0.2) }
  let(:js) { nc.jetstream }
  let(:psub) { js.pull_subscribe("cons.>", "c1", stream: "CONS") }
  let(:pulls) { nc.subscribe("$JS.API.CONSUMER.MSG.NEXT.CONS.c1") }
  let(:errors) { Queue.new }

  before do
    js.add_stream(name: "CONS", subjects: ["cons.>"])
    js.add_consumer("CONS", durable_name: "c1", ack_policy: "explicit")
    psub
    pulls
    nc.flush
  end

  after { nc.close }

  def publish(count, from: 0)
    count.times { |i| js.publish("cons.a", (from + i).to_s) }
  end

  def pulls_sent
    nc.flush
    Array.new(pulls.pending_queue.size) { JSON.parse(pulls.next_msg.data, symbolize_names: true) }
  end

  # Stops the server, which keeps the connection but sends nothing more,
  # until the block returns.
  def server_stopped
    pid = @s.server_pid
    Process.kill("STOP", pid)
    yield
  ensure
    Process.kill("CONT", pid)
  end

  describe "consume" do
    it "passes each message to the block, pulling as they go" do
      publish(20)
      got = Queue.new
      cc = psub.consume(max_messages: 5) do |msg|
        msg.ack
        got << msg.data
      end

      expect(Array.new(20) { got.pop(timeout: 5) }).to eql((0...20).map(&:to_s))
      cc.stop
      expect(cc.wait_closed(2)).to be(true)
      expect(cc).to be_closed

      first, *more = pulls_sent
      expect(first).to eql({batch: 5, expires: 30_000_000_000, idle_heartbeat: 15_000_000_000})
      # Pulls for more once fewer than half remain asked for.
      expect(more).not_to be_empty
      expect(more.map { |pull| pull[:batch] }).to all(be_between(3, 5))
    end

    it "keeps up to max_bytes asked for" do
      publish(3)
      got = Queue.new
      cc = psub.consume(max_bytes: 1024, expires: 2) { |msg| got << msg.data }

      expect(Array.new(3) { got.pop(timeout: 5) }).to eql(%w[0 1 2])
      cc.stop
      expect(pulls_sent.first).to eql({batch: 1_000_000, max_bytes: 1024, expires: 2_000_000_000, idle_heartbeat: 1_000_000_000})
    end

    it "pulls again when its pulls expire" do
      got = Queue.new
      cc = psub.consume(expires: 1, heartbeat: 0.5) { |msg| got << msg.data }
      sleep 2.5
      publish(1)

      expect(got.pop(timeout: 5)).to eql("0")
      cc.stop
      expect(pulls_sent.size).to be >= 2
    end

    it "drains the messages it has received" do
      publish(10)
      got = Queue.new
      cc = psub.consume(max_messages: 10) do |msg|
        sleep 0.05
        got << msg.data
      end
      sleep 0.1
      cc.drain

      expect(cc.wait_closed(5)).to be(true)
      expect(Array.new(got.size) { got.pop }).to eql((0...10).map(&:to_s))
    end

    it "stops and reports a deleted consumer" do
      cc = psub.consume(error_handler: ->(e) { errors << e }) { |msg| msg }
      eventually { expect(js.consumer_info("CONS", "c1").num_waiting).to eql(1) }
      js.delete_consumer("CONS", "c1")

      expect(errors.pop(timeout: 5)).to be_a(NATS::JetStream::Error::ConsumerDeleted)
      expect(cc.wait_closed(2)).to be(true)
    end

    it "reports the errors that the block raises, and goes on" do
      publish(2)
      got = Queue.new
      cc = psub.consume(error_handler: ->(e) { errors << e }) do |msg|
        raise "boom" if msg.data == "0"

        got << msg.data
      end

      expect(got.pop(timeout: 5)).to eql("1")
      expect(errors.pop(timeout: 1).message).to eql("boom")
      cc.stop
    end

    it "reports missing heartbeats, and pulls again" do
      got = Queue.new
      cc = psub.consume(expires: 2, heartbeat: 0.5, error_handler: ->(e) { errors << e }) { |msg| got << msg.data }
      eventually { expect(js.consumer_info("CONS", "c1").num_waiting).to eql(1) }
      pulls_sent

      server_stopped do
        expect(errors.pop(timeout: 3)).to be_a(NATS::JetStream::Error::NoHeartbeat)
      end
      publish(1)
      expect(got.pop(timeout: 5)).to eql("0")
      expect(pulls_sent).not_to be_empty
      cc.stop
    end

    it "pulls again after a reconnect" do
      publish(1)
      got = Queue.new
      cc = psub.consume(expires: 10) { |msg| got << msg.data }
      expect(got.pop(timeout: 5)).to eql("0")

      @s.kill_server
      @s.start_server(true)
      eventually(timeout: 10) { expect(nc).to be_connected }
      publish(1, from: 1)

      expect(got.pop(timeout: 10)).to eql("1")
      cc.stop
    end

    it "reports that the connection closed, and stops" do
      cc = psub.consume(error_handler: ->(e) { errors << e }) { |msg| msg }
      nc.close

      expect(errors.pop(timeout: 3)).to be_a(NATS::IO::ConnectionClosedError)
      expect(cc.wait_closed(2)).to be(true)
    end

    it "refuses invalid options" do
      expect { psub.consume }.to raise_error(ArgumentError)
      [
        {max_messages: 10, max_bytes: 1024},
        {max_messages: 0},
        {max_bytes: -1},
        {expires: 0.5},
        {expires: 2, heartbeat: 1.5},
        {heartbeat: 0.1},
        {threshold_messages: 0}
      ].each do |opts|
        expect { psub.consume(opts) { |msg| msg } }.to raise_error(ArgumentError)
      end
      expect(pulls_sent).to be_empty
    end
  end

  describe "messages" do
    it "returns each message from next" do
      publish(3)
      msgs = psub.messages(max_messages: 2)

      expect(Array.new(3) { msgs.next(timeout: 2).data }).to eql(%w[0 1 2])
      expect { msgs.next(timeout: 0.3) }.to raise_error(NATS::Timeout)
      msgs.stop
      expect { msgs.next }.to raise_error(NATS::JetStream::Error::MsgIteratorClosed)
      expect(msgs).to be_closed
    end

    it "yields each message from each" do
      publish(5)
      msgs = psub.messages
      got = []
      msgs.each do |msg|
        got << msg.data
        msgs.stop if got.size == 5
      end

      expect(got).to eql((0...5).map(&:to_s))
    end

    it "returns what it received after a drain, then closes" do
      publish(5)
      msgs = psub.messages(max_messages: 10)
      expect(msgs.next(timeout: 2).data).to eql("0")
      msgs.drain

      expect(msgs.map(&:data)).to eql(%w[1 2 3 4])
      expect { msgs.next }.to raise_error(NATS::JetStream::Error::MsgIteratorClosed)
    end

    it "raises ConsumerDeleted, then closes" do
      msgs = psub.messages
      expect { msgs.next(timeout: 0.5) }.to raise_error(NATS::Timeout)
      js.delete_consumer("CONS", "c1")

      expect { msgs.next(timeout: 5) }.to raise_error(NATS::JetStream::Error::ConsumerDeleted)
      expect { msgs.next }.to raise_error(NATS::JetStream::Error::MsgIteratorClosed)
    end

    it "raises NoHeartbeat when the heartbeats stop, and goes on" do
      msgs = psub.messages(expires: 2, heartbeat: 0.5)
      expect { msgs.next(timeout: 0.5) }.to raise_error(NATS::Timeout)

      server_stopped do
        expect { msgs.next(timeout: 3) }.to raise_error(NATS::JetStream::Error::NoHeartbeat)
      end
      publish(1)
      expect(msgs.next(timeout: 5).data).to eql("0")
      msgs.stop
    end

    it "closes with the connection" do
      msgs = psub.messages
      waiting = Thread.new do
        msgs.next
      rescue => e
        e
      end
      sleep 0.2
      nc.close

      expect(waiting.value).to be_a(NATS::JetStream::Error::MsgIteratorClosed)
      expect(waiting.value.message).to include("connection closed")
    end

    it "wakes a waiting next when stopped" do
      msgs = psub.messages
      waiting = Thread.new do
        msgs.next
      rescue => e
        e
      end
      sleep 0.2
      msgs.stop

      expect(waiting.value).to be_a(NATS::JetStream::Error::MsgIteratorClosed)
    end
  end
end

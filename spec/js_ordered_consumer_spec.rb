# frozen_string_literal: true

describe "JetStream ordered consumer" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-ordered")
    @s = NatsServerControl.new("nats://127.0.0.1:4735", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri, max_reconnect_attempts: -1, reconnect_time_wait: 0.2) }
  let(:js) { nc.jetstream }
  let(:errors) { Queue.new }

  before do
    js.add_stream(name: "ORD", subjects: ["ord.>"])
  end

  after { nc.close }

  def publish(count, from: 0, subject: "ord.a")
    count.times { |i| js.publish(subject, (from + i).to_s) }
  end

  def consumer_names
    resp = nc.request("$JS.API.CONSUMER.NAMES.ORD", "")
    JSON.parse(resp.data)["consumers"] || []
  end

  it "creates an ephemeral consumer that does not ack, in memory, with one replica" do
    oc = js.ordered_consumer("ORD", filter_subjects: ["ord.a"], name_prefix: "oc")

    expect(oc.consumer_name).to eql("oc_1")
    info = oc.consumer_info
    expect(info.name).to eql("oc_1")
    expect(info.config.durable_name).to be_nil
    expect(info.config.ack_policy).to eql("none")
    expect(info.config.mem_storage).to be(true)
    expect(info.config.num_replicas).to eql(1)
    expect(info.config.deliver_policy).to eql("all")
    expect(info.config.filter_subject).to eql("ord.a")
    expect(info.config.inactive_threshold).to eql(300)
  end

  it "raises for a stream that does not exist" do
    expect { js.ordered_consumer("NOPE") }.to raise_error(NATS::JetStream::Error::StreamNotFound)
  end

  describe "fetch" do
    it "fetches in order, from a new consumer each time" do
      publish(10)
      oc = js.ordered_consumer("ORD")
      first = oc.consumer_name

      expect(oc.fetch(5, timeout: 1).map(&:data)).to eql(%w[0 1 2 3 4])
      expect(oc.consumer_name).to eql(first)
      expect(oc.fetch(5, timeout: 1).map(&:data)).to eql(%w[5 6 7 8 9])
      expect(oc.consumer_name).not_to eql(first)
      expect(oc.consumer_info.config.opt_start_seq).to eql(6)
      # The consumers it no longer reads from are deleted.
      eventually { expect(consumer_names).to eql([oc.consumer_name]) }

      expect { oc.fetch(5, timeout: 0.5) }.to raise_error(NATS::Timeout)
      publish(1, from: 10)
      expect(oc.next(timeout: 1).data).to eql("10")
    end

    it "passes each message to a block" do
      publish(3)
      oc = js.ordered_consumer("ORD")
      got = []

      expect(oc.fetch(3, timeout: 1) { |msg| got << msg.data }.size).to eql(3)
      expect(got).to eql(%w[0 1 2])
    end

    it "is not read with messages too" do
      oc = js.ordered_consumer("ORD")
      expect { oc.fetch(1, timeout: 0.2) }.to raise_error(NATS::Timeout)

      expect { oc.messages }.to raise_error(NATS::JetStream::Error::OrderedConsumerUsedAsFetch)
      expect { oc.consume { |msg| msg } }.to raise_error(NATS::JetStream::Error::OrderedConsumerUsedAsFetch)
    end

    it "is not read by two fetches at once" do
      oc = js.ordered_consumer("ORD")
      fetch = Thread.new do
        oc.fetch(1, timeout: 1)
      rescue => e
        e
      end
      sleep 0.2

      expect { oc.fetch(1, timeout: 1) }.to raise_error(NATS::JetStream::Error::OrderedConsumerConcurrentRequests)
      expect(fetch.value).to be_a(NATS::Timeout)
    end
  end

  describe "messages" do
    it "iterates in order" do
      publish(5)
      oc = js.ordered_consumer("ORD")
      msgs = oc.messages

      expect(Array.new(5) { msgs.next(timeout: 2).data }).to eql(%w[0 1 2 3 4])
      expect { msgs.next(timeout: 0.3) }.to raise_error(NATS::Timeout)
      msgs.stop
      expect(msgs).to be_closed
      expect { msgs.next }.to raise_error(NATS::JetStream::Error::MsgIteratorClosed)
    end

    it "creates the consumer again when it is deleted, and goes on" do
      publish(3)
      oc = js.ordered_consumer("ORD")
      msgs = oc.messages(expires: 2)
      expect(Array.new(3) { msgs.next(timeout: 2).data }).to eql(%w[0 1 2])
      first = oc.consumer_name

      js.delete_consumer("ORD", first)
      publish(2, from: 3)

      expect(Array.new(2) { msgs.next(timeout: 5).data }).to eql(%w[3 4])
      expect(oc.consumer_name).not_to eql(first)
      expect(oc.consumer_info.config.opt_start_seq).to eql(4)
      msgs.stop
    end

    it "creates the consumer again when it misses a message" do
      publish(3)
      oc = js.ordered_consumer("ORD")
      msgs = oc.messages
      expect(msgs.next(timeout: 2).data).to eql("0")
      first = oc.consumer_name

      # A delivery that skips consumer sequences, after those on their way.
      sub = msgs.instance_variable_get(:@ctx).instance_variable_get(:@sub)
      wait_until { sub.pending_queue.size == 2 }
      skipped = NATS::Msg.new(subject: sub.subject, data: "skipped", nc: nc,
        reply: "$JS.ACK.ORD.#{first}.1.10.10.1700000000000000000.0")
      sub.synchronize { sub.dispatch(skipped) }
      expect(Array.new(2) { msgs.next(timeout: 2).data }).to eql(%w[1 2])

      publish(1, from: 3)
      expect(msgs.next(timeout: 5).data).to eql("3")
      expect(oc.consumer_name).not_to eql(first)
      expect(oc.consumer_info.config.opt_start_seq).to eql(4)
      msgs.stop
    end

    it "creates the consumer again after a reconnect" do
      publish(2)
      oc = js.ordered_consumer("ORD")
      msgs = oc.messages(expires: 2)
      expect(Array.new(2) { msgs.next(timeout: 2).data }).to eql(%w[0 1])

      # The consumer, in memory, is gone with the server.
      @s.kill_server
      @s.start_server(true)
      eventually(timeout: 10) { expect(nc).to be_connected }
      publish(2, from: 2)

      expect(Array.new(2) { msgs.next(timeout: 10).data }).to eql(%w[2 3])
      msgs.stop
    end

    it "is read by one iterator at a time, and goes on where the last stopped" do
      publish(4)
      oc = js.ordered_consumer("ORD")
      msgs = oc.messages
      expect(Array.new(2) { msgs.next(timeout: 2).data }).to eql(%w[0 1])

      expect { oc.messages }.to raise_error(NATS::JetStream::Error::OrderedConsumerConcurrentRequests)
      expect { oc.fetch(1) }.to raise_error(NATS::JetStream::Error::OrderedConsumerUsedAsConsume)
      msgs.stop

      again = oc.messages
      expect(Array.new(2) { again.next(timeout: 2).data }).to eql(%w[2 3])
      again.stop
    end

    it "drains the messages it has received" do
      publish(3)
      oc = js.ordered_consumer("ORD")
      msgs = oc.messages
      expect(msgs.next(timeout: 2).data).to eql("0")
      msgs.drain

      expect(msgs.map(&:data)).to eql(%w[1 2])
      expect(msgs).to be_closed
    end
  end

  describe "consume" do
    it "passes the messages in order, and goes on after the consumer is deleted" do
      publish(3)
      oc = js.ordered_consumer("ORD")
      got = Queue.new
      cc = oc.consume(expires: 2, error_handler: ->(e) { errors << e }) { |msg| got << msg.data }
      expect(Array.new(3) { got.pop(timeout: 5) }).to eql(%w[0 1 2])

      js.delete_consumer("ORD", oc.consumer_name)
      publish(2, from: 3)

      expect(Array.new(2) { got.pop(timeout: 5) }).to eql(%w[3 4])
      expect(errors.pop(timeout: 1)).to be_a(NATS::JetStream::Error::ConsumerDeleted)
      cc.stop
      expect(cc.wait_closed(2)).to be(true)
    end
  end

  describe "options" do
    before do
      js.publish("ord.a", "a1")
      js.publish("ord.b", "b1")
      js.publish("ord.a", "a2")
      js.publish("ord.c", "c1")
    end

    def first_data(params)
      msgs = js.ordered_consumer("ORD", params).messages
      Array.new(yield) { msgs.next(timeout: 2).data }
    ensure
      msgs&.stop
    end

    it "starts where the deliver policy says" do
      expect(first_data(deliver_policy: "last") { 1 }).to eql(%w[c1])
      expect(first_data(deliver_policy: "by_start_sequence", opt_start_seq: 3) { 2 }).to eql(%w[a2 c1])
      expect(first_data(deliver_policy: "last_per_subject") { 3 }).to eql(%w[b1 a2 c1])
      expect(first_data(deliver_policy: "by_start_time", opt_start_time: Time.now - 60) { 1 }).to eql(%w[a1])

      oc = js.ordered_consumer("ORD", deliver_policy: "new")
      msgs = oc.messages
      expect { msgs.next(timeout: 0.3) }.to raise_error(NATS::Timeout)
      js.publish("ord.d", "d1")
      expect(msgs.next(timeout: 2).data).to eql("d1")
      msgs.stop
    end

    it "reads the subjects of its filters" do
      expect(first_data(filter_subjects: ["ord.b", "ord.c"]) { 2 }).to eql(%w[b1 c1])
    end

    it "delivers the headers only" do
      oc = js.ordered_consumer("ORD", headers_only: true)
      msg = oc.next(timeout: 1)
      expect(msg.data).to eql("")
      expect(msg.header["Nats-Msg-Size"]).to eql("2")
    end

    it "refuses invalid options" do
      [
        {deliver_policy: "bogus"},
        {deliver_policy: "by_start_sequence"},
        {deliver_policy: "by_start_time"},
        {inactive_threshold: 0},
        {inactive_threshold: "5"},
        {filter_subjects: [""]},
        {max_reset_attempts: "1"}
      ].each do |params|
        expect { js.ordered_consumer("ORD", params) }.to raise_error(ArgumentError)
      end
    end
  end
end

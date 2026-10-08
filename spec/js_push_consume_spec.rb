# frozen_string_literal: true

describe "JetStream PushConsumer#consume" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-push-consume")
    @s = NatsServerControl.new("nats://127.0.0.1:4765", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:errors) { Queue.new }
  let(:nc) do
    NATS.connect(@s.uri).tap { |nc| nc.on_error { |e| errors << e } }
  end
  let(:js) { nc.jetstream }

  after { nc.close }

  before { js.add_stream(name: "PUSH", subjects: ["push.>"]) }

  def push_consumer(name, config = {})
    js.add_consumer("PUSH", durable_name: name, deliver_subject: "deliver.#{name}", ack_policy: "explicit", **config)
    js.push_consumer("PUSH", name)
  end

  it "passes the messages of the consumer to the block, leaving the acks to it" do
    3.times { |i| js.publish("push.a", i.to_s) }
    consumer = push_consumer("c")
    got = Queue.new
    cc = consumer.consume { |msg| got << msg }

    expect(cc).to be_a(NATS::JetStream::PushConsumeContext)
    expect(cc).to be_a(NATS::JetStream::ConsumeContext)
    msgs = Array.new(3) { got.pop(timeout: 2) }
    expect(msgs.map(&:data)).to eql(%w[0 1 2])
    # Like nats.go, consume does not ack for the block.
    eventually { expect(consumer.info.num_ack_pending).to eql(3) }
    msgs.each(&:ack_sync)
    expect(consumer.info.num_ack_pending).to eql(0)
    expect(cc.closed?).to be(false)

    cc.stop
    expect(cc.wait_closed(2)).to be(true)
    expect(cc.closed?).to be(true)
    expect(errors).to be_empty
  end

  it "raises ConsumerAlreadyConsuming while consuming, and consumes again once stopped" do
    consumer = push_consumer("c")
    cc = consumer.consume { |msg| msg.ack }

    expect { consumer.consume { |msg| msg.ack } }.to raise_error(NATS::JetStream::Error::ConsumerAlreadyConsuming, "nats: consumer is already consuming")
    cc.stop
    expect(cc.wait_closed(2)).to be(true)

    got = Queue.new
    cc = consumer.consume { |msg| got << msg.data }
    js.publish("push.a", "again")
    expect(got.pop(timeout: 2)).to eql("again")
    cc.stop
  end

  it "consumes in the deliver group of the consumer" do
    js.add_consumer("PUSH", durable_name: "q", deliver_subject: "deliver.q", deliver_group: "workers", ack_policy: "none")
    consumer = js.push_consumer("PUSH", "q")
    got = Queue.new
    cc = consumer.consume { |msg| got << msg.data }
    js.publish("push.a", "0")

    expect(got.pop(timeout: 2)).to eql("0")
    expect(js.consumer_info("PUSH", "q").push_bound).to be(true)
    cc.stop
  end

  it "drops what was received once stopped, and passes it once drained" do
    consumer = push_consumer("c", ack_wait: 30)
    started = Queue.new
    release = Queue.new
    got = Queue.new
    cc = consumer.consume do |msg|
      started << true
      release.pop
      got << msg.data
    end
    3.times { |i| js.publish("push.a", i.to_s) }
    started.pop(timeout: 2)
    eventually { expect(consumer.info.num_ack_pending).to eql(3) }

    cc.stop
    release << true
    expect(cc.wait_closed(2)).to be(true)
    expect(Array.new(got.size) { got.pop }).to eql(["0"])

    consumer2 = push_consumer("d", filter_subject: "push.b")
    got2 = Queue.new
    cc2 = consumer2.consume do |msg|
      sleep 0.1
      got2 << msg.data
    end
    3.times { |i| js.publish("push.b", i.to_s) }
    eventually { expect(consumer2.info.num_ack_pending).to eql(3) }
    cc2.drain
    expect(cc2.wait_closed(3)).to be(true)
    expect(Array.new(got2.size) { got2.pop }).to eql(%w[0 1 2])
  end

  it "answers the flow control requests of the consumer" do
    payload = "x" * 64 * 1024
    count = 300
    count.times { js.publish("push.a", payload) }
    consumer = push_consumer("fc", idle_heartbeat: 1, flow_control: true, ack_policy: "none")

    got = Queue.new
    cc = consumer.consume { |msg| got << msg }
    count.times do |i|
      msg = got.pop(timeout: 10)
      raise "stalled after #{i} messages" unless msg

      expect(msg.data.size).to eql(payload.size)
    end
    expect(errors).to be_empty
    cc.stop
  end

  it "does not pass the idle heartbeats to the block, and reports them missing" do
    consumer = push_consumer("hb", idle_heartbeat: 0.2)
    got = Queue.new
    errs = Queue.new
    cc = consumer.consume(error_handler: ->(err) { errs << err }) { |msg| got << msg }
    js.publish("push.a", "0")
    sleep 1
    expect(Array.new(got.size) { got.pop.data }).to eql(["0"])
    expect(errs).to be_empty

    js.delete_consumer("PUSH", "hb")
    err = errs.pop(timeout: 3)
    expect(err).to be_a(NATS::JetStream::Error::NoHeartbeat)
    expect(err.message).to eql("nats: no heartbeat received")
    # Missing heartbeats do not stop the consumption, as in nats.go.
    expect(cc.closed?).to be(false)
    cc.stop
    expect(cc.wait_closed(2)).to be(true)
    errs.clear
    sleep 0.6
    expect(errs).to be_empty
    expect(errors).to be_empty
  end

  it "reports what the block raises to the error handler, or else to the error callback" do
    consumer = push_consumer("c", ack_policy: "none")
    errs = Queue.new
    cc = consumer.consume(error_handler: ->(err) { errs << err }) { |msg| raise "boom #{msg.data}" }
    js.publish("push.a", "0")
    expect(errs.pop(timeout: 2).message).to eql("boom 0")
    cc.stop
    cc.wait_closed(2)

    cc = consumer.consume { |msg| raise "bang #{msg.data}" }
    js.publish("push.a", "1")
    expect(errors.pop(timeout: 2).message).to eql("bang 1")
    cc.stop
  end

  it "closes with the connection" do
    consumer = push_consumer("c")
    cc = consumer.consume { |msg| msg }
    nc.close
    expect(cc.wait_closed(2)).to be(true)
  end

  it "checks its arguments" do
    consumer = push_consumer("c")
    expect { consumer.consume }.to raise_error(ArgumentError, "nats: handler cannot be empty")
    expect { consumer.consume(error_handler: 1) { |msg| msg } }.to raise_error(ArgumentError, /invalid error_handler/)
    cc = consumer.consume { |msg| msg }
    cc.stop
  end
end

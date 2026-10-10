# frozen_string_literal: true

describe "JetStream push subscription heartbeats and flow control" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-push-hb")
    @s = NatsServerControl.new("nats://127.0.0.1:4764", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
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

  # Counts the control messages that come to the deliver subject of a
  # subscription, with a subscription of its own.
  def control_msgs(sub)
    raw = nc.subscribe(sub.subject)
    nc.flush
    raw
  end

  def status_msgs(raw)
    Array.new(raw.pending_queue.size) { raw.next_msg }.select { |msg| msg.header&.fetch("Status", nil) == "100" }
  end

  it "does not return the idle heartbeats from next_msg" do
    2.times { |i| js.publish("push.a", i.to_s) }
    sub = js.subscribe("push.a", idle_heartbeat: 0.2)
    raw = control_msgs(sub)

    expect(Array.new(2) { sub.next_msg(timeout: 1).data }).to eql(%w[0 1])
    expect { sub.next_msg(timeout: 1) }.to raise_error(NATS::Timeout)
    expect(status_msgs(raw)).not_to be_empty
    expect(sub.consumer_info.config.idle_heartbeat).to eql(0.2)
    expect(errors).to be_empty
    sub.unsubscribe
  end

  it "does not pass the idle heartbeats to the block" do
    got = Queue.new
    sub = js.subscribe("push.a", idle_heartbeat: 0.2) { |msg| got << msg }
    raw = control_msgs(sub)
    js.publish("push.a", "0")

    sleep 1
    expect(status_msgs(raw)).not_to be_empty
    msgs = Array.new(got.size) { got.pop }
    expect(msgs.map(&:data)).to eql(["0"])
    expect(errors).to be_empty
    sub.unsubscribe
  end

  it "skips the idle heartbeats of a consumer it binds to" do
    js.add_consumer("PUSH", durable_name: "bound", deliver_subject: "deliver.bound", idle_heartbeat: 0.2)
    js.publish("push.a", "0")
    sub = js.subscribe("push.a", durable: "bound", stream: "PUSH")

    expect(sub.next_msg(timeout: 1).data).to eql("0")
    expect { sub.next_msg(timeout: 1) }.to raise_error(NATS::Timeout)
    expect(errors).to be_empty
    sub.unsubscribe
  end

  it "answers the flow control requests, once the messages before them were delivered" do
    fc_replies = nc.subscribe("$JS.FC.>")
    nc.flush
    payload = "x" * 64 * 1024
    count = 300
    count.times { js.publish("push.a", payload) }

    got = Queue.new
    sub = js.subscribe("push.a", idle_heartbeat: 1, flow_control: true) do |msg|
      got << msg
    end

    received = 0
    while received < count
      msg = got.pop(timeout: 10)
      raise "stalled after #{received} messages" unless msg

      expect(msg.data.size).to eql(payload.size)
      received += 1
    end
    nc.flush
    expect(fc_replies.pending_queue.size).to be > 0
    expect(sub.consumer_info.num_ack_pending).to eql(0)
    expect(errors).to be_empty
    sub.unsubscribe
  end

  it "answers the flow control requests of a subscription without a block" do
    payload = "x" * 64 * 1024
    count = 300
    count.times { js.publish("push.a", payload) }
    sub = js.subscribe("push.a", idle_heartbeat: 1, flow_control: true)

    count.times do |i|
      msg = sub.next_msg(timeout: 10)
      expect(msg.data.size).to eql(payload.size), "message #{i}"
      msg.ack
    end
    expect(errors).to be_empty
    sub.unsubscribe
  end

  it "reports a consumer that sends no heartbeats as not active" do
    sub = js.subscribe("push.a", durable: "gone", idle_heartbeat: 0.2) { |msg| msg }
    sleep 0.6
    expect(errors).to be_empty

    js.delete_consumer("PUSH", "gone")
    err = errors.pop(timeout: 3)
    expect(err).to be_a(NATS::JetStream::Error::ConsumerNotActive)
    expect(err.message).to eql("nats: consumer not active")
    sub.unsubscribe
  end

  it "stops checking once unsubscribed" do
    sub = js.subscribe("push.a", idle_heartbeat: 0.2)
    sub.unsubscribe
    sleep 1
    expect(errors).to be_empty
  end

  it "does not check a consumer without heartbeats" do
    sub = js.subscribe("push.a") { |msg| msg }
    sleep 1
    expect(errors).to be_empty
    sub.unsubscribe
  end

  it "leaves the acks to the block with manual_ack" do
    got = Queue.new
    sub = js.subscribe("push.a", durable: "manual", manual_ack: true) { |msg| got << msg }
    js.publish("push.a", "0")
    msg = got.pop(timeout: 2)

    eventually { expect(sub.consumer_info.num_ack_pending).to eql(1) }
    msg.ack_sync
    expect(sub.consumer_info.num_ack_pending).to eql(0)
    sub.unsubscribe
  end
end

# frozen_string_literal: true

describe "Subscription#set_pending_limits" do
  before(:all) do
    @s = NatsServerControl.new("nats://127.0.0.1:4893", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
  end

  before do
    @errors = Queue.new
    @nc = NATS.connect(@s.uri)
    @nc.on_error { |e| @errors << e }
  end

  after do
    @nc.close
  end

  it "should raise the limits of a subscription without blocking the reader" do
    sub = @nc.subscribe("raise", pending_msgs_limit: 2)
    expect(sub.pending_limits).to eql([2, NATS::IO::DEFAULT_SUB_PENDING_BYTES_LIMIT])

    expect(sub.set_pending_limits(10, 1024)).to be_nil
    expect(sub.pending_limits).to eql([10, 1024])
    10.times { |i| @nc.publish("raise", "msg-#{i}") }
    # The reader would block on a full queue, and the PONG not come.
    @nc.flush(2)

    expect(sub.pending_queue.size).to eql(10)
    expect(sub.dropped).to eql(0)
    expect(Array.new(10) { sub.next_msg(timeout: 1).data }).to eql(Array.new(10) { |i| "msg-#{i}" })
  end

  it "should also resize the queue when the limits are written one by one" do
    sub = @nc.subscribe("write", pending_msgs_limit: 2)
    sub.pending_msgs_limit = 5
    sub.pending_bytes_limit = 1024
    6.times { @nc.publish("write", "x") }
    @nc.flush(2)

    expect(sub.pending_limits).to eql([5, 1024])
    expect(sub.pending_queue.size).to eql(5)
    expect(sub.dropped).to eql(1)
  end

  it "should drop the messages beyond lowered limits as a slow consumer" do
    sub = @nc.subscribe("lower")
    sub.set_pending_limits(3, -1)
    5.times { @nc.publish("lower", "x") }
    @nc.flush(2)

    expect(sub.pending_queue.size).to eql(3)
    expect(sub.dropped).to eql(2)
    expect(@errors.pop).to be_a(NATS::IO::SlowConsumer)

    # Bytes only: the message that makes 10 bytes pending is the last one.
    sub = @nc.subscribe("bytes")
    sub.set_pending_limits(-1, 10)
    5.times { @nc.publish("bytes", "four") }
    @nc.flush(2)
    expect(sub.pending_queue.size).to eql(3)
    expect(sub.dropped).to eql(2)
  end

  it "should not limit for negative limits, like nats.go" do
    received = Queue.new
    gate = Queue.new
    sub = @nc.subscribe("unlimited", pending_msgs_limit: -1, pending_bytes_limit: -1) do |msg|
      gate.pop
      received << msg
    end
    expect(sub.pending_limits).to eql([-1, -1])

    100.times { @nc.publish("unlimited", "x" * 100) }
    @nc.flush(2)
    expect(sub.dropped).to eql(0)

    100.times { gate << true }
    100.times { received.pop }
    expect(sub.dropped).to eql(0)
  end

  it "should refuse zero limits, like ErrInvalidArg of nats.go" do
    sub = @nc.subscribe("zero", pending_msgs_limit: 4)
    [[0, 10], [10, 0], [nil, 10], [10, "1"]].each do |msgs, bytes|
      expect { sub.set_pending_limits(msgs, bytes) }.to raise_error(ArgumentError, /invalid argument/)
    end
    expect { sub.pending_msgs_limit = 0 }.to raise_error(ArgumentError)
    expect(sub.pending_limits).to eql([4, NATS::IO::DEFAULT_SUB_PENDING_BYTES_LIMIT])

    subs = @nc.num_subscriptions
    expect { @nc.subscribe("zero", pending_msgs_limit: 0) }.to raise_error(ArgumentError)
    expect { @nc.subscribe("zero", pending_bytes_limit: 0) }.to raise_error(ArgumentError)
    expect(@nc.num_subscriptions).to eql(subs)
  end

  it "should raise BadSubscription for a closed subscription" do
    sub = @nc.subscribe("closed")
    sub.unsubscribe

    expect { sub.set_pending_limits(10, 10) }.to raise_error(NATS::IO::BadSubscription)
    expect { sub.pending_limits }.to raise_error(NATS::IO::BadSubscription)
  end
end

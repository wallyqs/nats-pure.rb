# frozen_string_literal: true

describe "Subscription#valid?, #pending and #queued_msgs" do
  before(:all) do
    @s = NatsServerControl.new("nats://127.0.0.1:4895", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
  end

  before do
    @nc = NATS.connect(@s.uri)
  end

  after do
    @nc.close
  end

  it "should tell whether a subscription is valid, like IsValid of nats.go" do
    sub = @nc.subscribe("valid")
    expect(sub.valid?).to be(true)
    sub.unsubscribe
    expect(sub.valid?).to be(false)

    # Valid until it got its max messages.
    got = Queue.new
    sub = @nc.subscribe("max") { |msg| got << msg }
    sub.unsubscribe(2)
    expect(sub.valid?).to be(true)
    @nc.publish("max", "1")
    @nc.flush
    got.pop
    expect(sub.valid?).to be(true)
    @nc.publish("max", "2")
    @nc.flush
    got.pop
    expect(sub.valid?).to be(false)

    sub = @nc.subscribe("drain") { |msg| }
    sub.drain
    sleep 0.05 while sub.draining?
    expect(sub.valid?).to be(false)

    nc = NATS.connect(@s.uri)
    sub = nc.subscribe("close")
    expect(sub.valid?).to be(true)
    nc.close
    expect(sub.valid?).to be(false)
  end

  it "should return the pending messages and bytes, like Pending of nats.go" do
    sub = @nc.subscribe("sync.pending", queue: "workers")
    expect(sub.subject).to eql("sync.pending")
    expect(sub.queue).to eql("workers")
    expect(sub.pending).to eql([0, 0])

    %w[a bb ccc].each { |data| @nc.publish("sync.pending", data) }
    @nc.flush
    expect(sub.pending).to eql([3, 6])
    expect(sub.queued_msgs).to eql(3)

    sub.next_msg(timeout: 1)
    expect(sub.pending).to eql([2, 5])
    expect(sub.queued_msgs).to eql(2)

    sub.unsubscribe
    expect { sub.pending }.to raise_error(NATS::IO::BadSubscription)
    expect { sub.queued_msgs }.to raise_error(NATS::IO::BadSubscription)
  end

  it "should count the messages that wait for the callback" do
    gate = Queue.new
    started = Queue.new
    sub = @nc.subscribe("async.pending") do
      started << true
      gate.pop
    end

    4.times { @nc.publish("async.pending", "data") }
    @nc.flush
    started.pop

    # The one being processed no longer waits.
    expect(sub.pending).to eql([3, 12])
    expect(sub.delivered).to eql(4)

    4.times { gate << true }
    3.times { started.pop }
    sleep 0.05 until sub.pending == [0, 0]
    expect(sub.queued_msgs).to eql(0)
  end
end

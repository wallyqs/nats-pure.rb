# frozen_string_literal: true

describe "Client - default subscription pending limits" do
  before(:all) do
    @s = NatsServerControl.new("nats://127.0.0.1:4926", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
  end

  let(:url) { "nats://127.0.0.1:4926" }

  it "uses the limits of the connection for subscriptions without their own, like SubChanLen of nats.go" do
    nc = NATS.connect(url, sub_pending_msgs_limit: 3, sub_pending_bytes_limit: 1024)
    sync_sub = nc.subscribe("limits")
    cb_sub = nc.subscribe("limits") { |_msg| }
    own_sub = nc.subscribe("limits", pending_msgs_limit: 10)
    expect(sync_sub.pending_limits).to eq([3, 1024])
    expect(cb_sub.pending_limits).to eq([3, 1024])
    expect(own_sub.pending_limits).to eq([10, 1024])
    nc.close
  end

  it "drops what is beyond them, as a slow consumer" do
    errors = Queue.new
    nc = NATS.connect(url, sub_pending_msgs_limit: 3)
    nc.on_error { |e| errors << e }
    sub = nc.subscribe("slow")
    5.times { |i| nc.publish("slow", i.to_s) }
    nc.flush

    expect(errors.pop(timeout: 2)).to be_a(NATS::IO::SlowConsumer)
    expect(Array.new(3) { sub.next_msg.data }).to eq(%w[0 1 2])
    expect(sub.dropped).to eq(2)
    nc.close
  end

  it "keeps the defaults of the client without them" do
    nc = NATS.connect(url)
    expect(nc.subscribe("x").pending_limits).to eq([NATS::IO::DEFAULT_SUB_PENDING_MSGS_LIMIT, NATS::IO::DEFAULT_SUB_PENDING_BYTES_LIMIT])
    nc.close
  end

  it "refuses limits of zero, like SetPendingLimits" do
    expect { NATS.connect(url, sub_pending_msgs_limit: 0) }.to raise_error(NATS::IO::InvalidArg)
    expect { NATS.connect(url, sub_pending_bytes_limit: 0) }.to raise_error(NATS::IO::InvalidArg)
    expect { NATS.connect(url, sub_pending_msgs_limit: "10") }.to raise_error(NATS::IO::InvalidArg)
  end
end

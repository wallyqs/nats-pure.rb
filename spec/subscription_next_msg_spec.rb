# frozen_string_literal: true

describe "Subscription#next_msg" do
  before(:all) do
    @s = NatsServerControl.new("nats://127.0.0.1:4872", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
  end

  it "should raise SyncSubRequired on a subscription with a callback" do
    nc = NATS.connect(@s.uri)
    msgs = Queue.new
    sub = nc.subscribe("async") { |msg| msgs << msg }

    expect { sub.next_msg }.to raise_error(NATS::IO::SyncSubRequired, "nats: illegal call on an async subscription")
    expect { sub.next_msg(timeout: 0.1) }.to raise_error(NATS::IO::ClientError)

    # The callback still gets the messages.
    nc.publish("async", "hi")
    expect(Timeout.timeout(2) { msgs.pop }.data).to eql("hi")

    nc.close
  end

  it "should still return the messages of a subscription without a callback" do
    nc = NATS.connect(@s.uri)
    sub = nc.subscribe("sync")
    nc.publish("sync", "hi")

    expect(sub.next_msg(timeout: 1).data).to eql("hi")
    expect { sub.next_msg(timeout: 0.1) }.to raise_error(NATS::Timeout)

    nc.close
  end
end

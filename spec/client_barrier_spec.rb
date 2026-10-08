# frozen_string_literal: true

describe "Client - barrier" do
  before(:all) do
    @s = NatsServerControl.new("nats://127.0.0.1:4870", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
  end

  it "should run the block right away without subscriptions with a callback" do
    nc = NATS.connect(@s.uri)
    nc.subscribe("sync") # without a callback, so it does not count

    ran = false
    nc.barrier { ran = true }
    expect(ran).to be(true)

    nc.close
  end

  it "should run the block once the messages received so far are processed" do
    nc = NATS.connect(@s.uri)

    processed = []
    nc.subscribe("slow") do |msg|
      sleep 0.01
      processed << msg.data
    end
    20.times { |i| nc.publish("slow", i.to_s) }
    # Once the PONG is back, the messages before it have been received.
    nc.flush

    seen = Queue.new
    expect(nc.barrier { seen << processed.dup }).to be_nil
    expect(Timeout.timeout(5) { seen.pop }).to eql((0..19).map(&:to_s))

    nc.close
  end

  it "should run the block once, after every subscription passed it" do
    nc = NATS.connect(@s.uri)

    a = []
    b = []
    nc.subscribe("bar.a") do |msg|
      sleep 0.05
      a << msg
    end
    nc.subscribe("bar.b") do |msg|
      sleep 0.01
      b << msg
    end
    5.times { nc.publish("bar.a") }
    10.times { nc.publish("bar.b") }
    nc.flush

    runs = Queue.new
    nc.barrier { runs << [a.size, b.size] }
    expect(Timeout.timeout(5) { runs.pop }).to eql([5, 10])
    sleep 0.2
    expect(runs).to be_empty

    nc.close
  end

  it "should wait for messages processed concurrently" do
    nc = NATS.connect(@s.uri)

    done = Queue.new
    nc.subscribe("concurrent", processing_concurrency: 5) do |msg|
      sleep rand * 0.05
      done << msg.data
    end
    30.times { |i| nc.publish("concurrent", i.to_s) }
    nc.flush

    seen = Queue.new
    nc.barrier { seen << done.size }
    expect(Timeout.timeout(5) { seen.pop }).to eql(30)

    nc.close
  end

  it "should not wait for messages received after it" do
    nc = NATS.connect(@s.uri)

    gate = Queue.new
    processed = []
    nc.subscribe("after") do |msg|
      gate.pop if msg.data == "block"
      processed << msg.data
    end
    nc.publish("after", "first")
    nc.flush

    seen = Queue.new
    nc.barrier { seen << processed.dup }
    expect(Timeout.timeout(5) { seen.pop }).to eql(["first"])

    # It waits for a callback that is still running.
    nc.publish("after", "block")
    nc.flush
    nc.barrier { seen << processed.dup }
    sleep 0.1
    expect(seen).to be_empty
    gate << true
    expect(Timeout.timeout(5) { seen.pop }).to eql(%w[first block])

    nc.close
  end

  it "should run a barrier set from a callback once the callback returns" do
    nc = NATS.connect(@s.uri)

    events = Queue.new
    nc.subscribe("inner") do
      nc.barrier { events << :barrier }
      sleep 0.05
      events << :callback
    end
    nc.publish("inner")

    expect(Timeout.timeout(5) { [events.pop, events.pop] }).to eql(%i[callback barrier])

    nc.close
  end

  it "should hand errors of the block to on_error" do
    nc = NATS.connect(@s.uri)
    errors = Queue.new
    nc.on_error { |e| errors << e }

    nc.subscribe("err") { sleep 0.01 }
    nc.publish("err")
    nc.flush
    nc.barrier { raise "boom" }
    expect(Timeout.timeout(5) { errors.pop }.message).to eql("boom")

    nc.close
  end

  it "should raise ConnectionClosedError once closed" do
    nc = NATS.connect(@s.uri)
    nc.close

    expect { nc.barrier {} }.to raise_error(NATS::IO::ConnectionClosedError)
  end
end

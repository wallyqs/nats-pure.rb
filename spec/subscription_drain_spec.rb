# frozen_string_literal: true

describe "Subscription - drain, pending stats and closed handler" do
  before(:all) do
    @s = NatsServerControl.new("nats://127.0.0.1:4871", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
  end

  describe "#drain" do
    it "should process the pending messages, then close the subscription" do
      nc = NATS.connect(@s.uri)
      gate = Queue.new
      processed = []
      closed = Queue.new

      sub = nc.subscribe("drain.me") do |msg|
        gate.pop
        processed << msg.data
      end
      sub.on_close { |subject| closed << subject }
      expect(sub.draining?).to be(false)

      5.times { |i| nc.publish("drain.me", i.to_s) }
      nc.flush

      sub.drain
      expect(sub.draining?).to be(true)
      # Unsubscribed: no more messages come.
      nc.publish("drain.me", "late")
      nc.flush

      5.times { gate << true }
      expect(Timeout.timeout(5) { closed.pop }).to eql("drain.me")
      expect(processed).to eql(%w[0 1 2 3 4])
      expect(sub.draining?).to be(false)
      expect(nc.num_subscriptions).to eql(0)
      expect { sub.drain }.to raise_error(NATS::IO::BadSubscription)

      gate << true
      sleep 0.1
      expect(processed).to eql(%w[0 1 2 3 4])
      nc.close
    end

    it "should let next_msg take the messages of a drained subscription without a callback" do
      nc = NATS.connect(@s.uri)
      sub = nc.subscribe("drain.sync")
      3.times { |i| nc.publish("drain.sync", i.to_s) }
      nc.flush

      sub.drain
      expect(sub.draining?).to be(true)
      expect(3.times.map { sub.next_msg.data }).to eql(%w[0 1 2])
      wait_until(timeout: 5) { !sub.draining? }
      expect(nc.num_subscriptions).to eql(0)

      nc.close
    end

    it "should raise when the connection is closed or draining" do
      nc = NATS.connect(@s.uri)
      sub = nc.subscribe("drain.closed") {}
      nc.close
      expect { sub.drain }.to raise_error(NATS::IO::ConnectionClosedError)

      nc = NATS.connect(@s.uri, drain_timeout: 2)
      sub = nc.subscribe("drain.conn") { sleep 0.2 }
      nc.publish("drain.conn")
      nc.flush
      nc.drain
      expect { sub.drain }.to raise_error(NATS::IO::ConnectionDrainingError)
      wait_until(timeout: 5) { nc.closed? }
      # Done with the drain of the connection.
      expect(sub.draining?).to be(false)
    end
  end

  describe "#dropped and #max_pending" do
    it "should count the messages dropped and the most pending" do
      nc = NATS.connect(@s.uri)
      nc.on_error {}
      gate = Queue.new
      processed = Queue.new

      sub = nc.subscribe("slow", pending_msgs_limit: 2) do |msg|
        gate.pop
        processed << msg
      end
      expect(sub.dropped).to eql(0)
      expect(sub.max_pending).to eql([0, 0])

      10.times { nc.publish("slow", "abc") }
      nc.flush
      wait_until(timeout: 2) { sub.received == 10 }

      expect(sub.dropped).to be >= 7
      expect(sub.max_pending).to eql([2, 6])

      10.times { gate << true }
      wait_until(timeout: 2) { processed.size + sub.dropped == 10 }

      sub.clear_max_pending
      expect(sub.max_pending).to eql([0, 0])
      nc.publish("slow", "abcd")
      nc.flush
      wait_until(timeout: 2) { processed.size + sub.dropped == 11 }
      expect(sub.max_pending).to eql([1, 4])

      nc.close
    end
  end

  describe "#on_close" do
    it "should be called once unsubscribed and the pending messages processed" do
      nc = NATS.connect(@s.uri)
      events = Queue.new
      gate = Queue.new

      sub = nc.subscribe("closing") do |msg|
        gate.pop
        events << msg.data
      end
      sub.on_close { |subject| events << "closed #{subject}" }
      nc.publish("closing", "a")
      nc.flush
      sub.unsubscribe
      sleep 0.1
      expect(events).to be_empty

      gate << true
      expect(Timeout.timeout(5) { [events.pop, events.pop] }).to eql(["a", "closed closing"])
      nc.close
      sleep 0.1
      expect(events).to be_empty
    end

    it "should be called once the max messages were received and processed" do
      nc = NATS.connect(@s.uri)
      events = Queue.new

      sub = nc.subscribe("closing.max", max: 2) { |msg| events << msg.data }
      sub.on_close { |subject| events << "closed #{subject}" }
      3.times { |i| nc.publish("closing.max", i.to_s) }

      expect(Timeout.timeout(5) { 3.times.map { events.pop } }).to eql(["0", "1", "closed closing.max"])
      nc.close
    end

    it "should be called when the connection closes" do
      nc = NATS.connect(@s.uri)
      closed = []
      a = nc.subscribe("closing.a") {}
      a.on_close { |subject| closed << subject }
      b = nc.subscribe("closing.b") {}
      b.on_close { |subject| closed << subject }

      nc.close
      expect(closed).to contain_exactly("closing.a", "closing.b")
    end
  end
end

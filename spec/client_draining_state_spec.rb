# frozen_string_literal: true

describe "Client - draining state once the drain is over" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-draining-state")
    @s = NatsServerControl.new("nats://127.0.0.1:4881", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:errors) { Queue.new }

  it "reports a drained connection as not draining once it closed, like IsDraining" do
    nc = NATS.connect(@s.uri)
    closed = Queue.new
    nc.on_close { closed << true }
    sub = nc.subscribe("foo") { |msg| msg }
    nc.flush

    nc.drain
    expect(nc.draining?).to be(true)
    expect(closed.pop(timeout: 5)).to be(true)
    expect(nc.closed?).to be(true)
    expect(nc.draining?).to be(false)
    expect(sub.draining?).to be(false)
  end

  it "reports a subscription that was draining when the connection closed as not draining" do
    nc = NATS.connect(@s.uri)
    # A message that is never taken keeps the drain from ending.
    sub = nc.subscribe("foo")
    nc.publish("foo", "pending")
    nc.flush
    sub.drain
    expect(sub.draining?).to be(true)

    nc.close
    expect(sub.draining?).to be(false)
  end

  it "reports the subscriptions of a stopped service as not draining once drained" do
    nc = NATS.connect(@s.uri)
    nc.on_error { |e| errors << e }
    service = nc.services.add(name: "drained", version: "1.0.0")
    endpoint = service.endpoints.add("ep") { |req| req.respond("ok") }
    expect(nc.request("ep", "", timeout: 1).data).to eql("ok")
    monitors = service.instance_variable_get(:@monitoring).instance_variable_get(:@monitors)
    expect(monitors).not_to be_empty

    service.stop
    sub = endpoint.subscription
    wait_until(timeout: 5) { !sub.draining? }
    expect(sub.draining?).to be(false)
    expect(sub.valid?).to be(false)
    wait_until(timeout: 5) { monitors.none?(&:draining?) }
    expect(monitors.map(&:valid?)).to all(be(false))
    expect { nc.request("ep", "", timeout: 0.5) }.to raise_error(NATS::IO::NoRespondersError)
    expect(errors).to be_empty
    nc.close
  end

  it "lets the requests of a stopped endpoint that came before finish" do
    nc = NATS.connect(@s.uri)
    nc.on_error { |e| errors << e }
    started = Queue.new
    release = Queue.new
    service = nc.services.add(name: "slow", version: "1.0.0")
    endpoint = service.endpoints.add("slow") do |req|
      started << true
      release.pop
      req.respond("done")
    end
    inbox = nc.new_inbox
    replies = nc.subscribe(inbox)
    nc.publish("slow", "", inbox)
    started.pop(timeout: 2)

    service.stop
    expect(endpoint.subscription.draining?).to be(true)
    release << true
    expect(replies.next_msg(timeout: 2).data).to eql("done")
    wait_until(timeout: 5) { !endpoint.subscription.draining? }
    expect(errors).to be_empty
    nc.close
  end

  it "reports the subscription of a drained consume as not draining" do
    nc = NATS.connect(@s.uri)
    js = nc.jetstream
    js.add_stream(name: "DRAIN", subjects: ["drain.>"])
    js.publish("drain.a", "1")
    psub = js.pull_subscribe("drain.a", "d")
    got = Queue.new
    cc = psub.consume { |msg| got << msg }
    expect(got.pop(timeout: 2).data).to eql("1")
    sub = cc.instance_variable_get(:@messages).instance_variable_get(:@sub)

    cc.drain
    wait_until(timeout: 5) { cc.closed? }
    wait_until(timeout: 5) { !sub.draining? }
    expect(sub.draining?).to be(false)
    nc.close
  end
end

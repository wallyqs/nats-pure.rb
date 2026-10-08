# frozen_string_literal: true

describe "JetStream consumer durations" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-durations")
    @s = NatsServerControl.new("nats://127.0.0.1:4761", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:creates) { nc.subscribe("$JS.API.CONSUMER.CREATE.DUR.>") }

  before do
    js.add_stream(name: "DUR", subjects: ["dur.>"])
    creates
    nc.flush
  end

  after { nc.close }

  def config_sent
    nc.flush
    JSON.parse(creates.next_msg.data, symbolize_names: true)[:config]
  end

  it "sends fractions of a second as exact nanoseconds" do
    info = js.add_consumer("DUR", durable_name: "c", ack_wait: 0.25, inactive_threshold: 2.5,
      idle_heartbeat: 0.5, deliver_subject: "deliver", flow_control: true)

    expect(config_sent.slice(:ack_wait, :inactive_threshold, :idle_heartbeat))
      .to eql({ack_wait: 250_000_000, inactive_threshold: 2_500_000_000, idle_heartbeat: 500_000_000})
    expect(info.config.to_h.slice(:ack_wait, :inactive_threshold, :idle_heartbeat))
      .to eql({ack_wait: 0.25, inactive_threshold: 2.5, idle_heartbeat: 0.5})

    # Like time.Duration of nats.go, 0.1 seconds is 100ms, not a float error away.
    info = js.add_consumer("DUR", durable_name: "d", ack_wait: 0.1)
    expect(config_sent[:ack_wait]).to eql(100_000_000)
    expect(js.consumer_info("DUR", "d").config.ack_wait).to eql(0.1)
    expect(info.config.ack_wait).to eql(0.1)
  end

  it "keeps whole seconds as Integers, both ways" do
    info = js.add_consumer("DUR", durable_name: "c", ack_wait: 30, inactive_threshold: 60.0)

    expect(config_sent.slice(:ack_wait, :inactive_threshold))
      .to eql({ack_wait: 30_000_000_000, inactive_threshold: 60_000_000_000})
    expect(info.config.ack_wait).to eql(30)
    expect(info.config.inactive_threshold).to eql(60)
  end

  it "sends a fetched config with fractions back unchanged" do
    js.add_consumer("DUR", durable_name: "c", ack_wait: 1.5, max_ack_pending: 10)
    config_sent

    config = js.consumer_info("DUR", "c").config
    config.max_ack_pending = 20
    info = js.update_consumer("DUR", config)

    expect(config_sent[:ack_wait]).to eql(1_500_000_000)
    expect(info.config.ack_wait).to eql(1.5)
    expect(info.config.max_ack_pending).to eql(20)
  end

  it "decodes the durations that the server set" do
    nc.request("$JS.API.CONSUMER.CREATE.DUR.raw",
      {stream_name: "DUR", config: {name: "raw", ack_policy: "explicit", ack_wait: 1_234_567_890}}.to_json)

    expect(js.consumer_info("DUR", "raw").config.ack_wait).to eql(1.23456789)
  end

  it "leaves backoff and max_expires in nanoseconds" do
    info = js.add_consumer("DUR", durable_name: "c", ack_wait: 2, max_deliver: 3,
      backoff: [1_000_000_000, 1_500_000_000], max_expires: 5_000_000_000)

    expect(config_sent.slice(:backoff, :max_expires))
      .to eql({backoff: [1_000_000_000, 1_500_000_000], max_expires: 5_000_000_000})
    expect(info.config.backoff).to eql([1_000_000_000, 1_500_000_000])
    expect(info.config.max_expires).to eql(5_000_000_000)
  end

  it "refuses durations that are not numbers" do
    [{ack_wait: "1"}, {inactive_threshold: Float::INFINITY}, {idle_heartbeat: Float::NAN, deliver_subject: "d"},
      {priority_timeout: :one}].each do |config|
      expect { js.add_consumer("DUR", config.merge(durable_name: "c")) }.to raise_error(ArgumentError)
    end
  end

  it "redelivers after a fraction of a second ack wait" do
    js.add_consumer("DUR", durable_name: "c", ack_wait: 0.5)
    js.publish("dur.a", "1")
    psub = js.pull_subscribe("dur.a", "c", stream: "DUR")

    first = psub.fetch(1).first
    expect(first.metadata.num_delivered).to eql(1)
    started = NATS::MonotonicTime.now
    again = psub.fetch(1, timeout: 3).first
    expect(again.metadata.num_delivered).to eql(2)
    expect(NATS::MonotonicTime.now - started).to be < 1.5
  end

  it "takes a fractional inactive threshold for an ordered consumer" do
    oc = js.ordered_consumer("DUR", inactive_threshold: 1.5)
    expect(oc.consumer_info.config.inactive_threshold).to eql(1.5)
  end
end

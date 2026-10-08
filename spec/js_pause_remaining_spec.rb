# frozen_string_literal: true

describe "JetStream pause_remaining" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-pause-remaining")
    @s = NatsServerControl.new("nats://127.0.0.1:4741", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  before do
    js.add_stream(name: "PAUSE", subjects: ["pause"])
    js.add_consumer("PAUSE", durable_name: "c")
  end

  after { nc.close }

  it "keeps the fraction of a second of the server's value, as nats.go does" do
    resp = js.pause_consumer("PAUSE", "c", Time.now + 1.5)
    expect(resp.pause_remaining).to be_a(Float)
    expect(resp.pause_remaining).to be_between(1.0, 1.5)

    info = js.consumer_info("PAUSE", "c")
    expect(info.pause_remaining).to be_a(Float)
    expect(info.pause_remaining).to be > 0
    expect(info.pause_remaining).to be <= resp.pause_remaining
  end

  it "is above 0 in the last second of a pause, instead of rounded down to 0" do
    js.pause_consumer("PAUSE", "c", Time.now + 0.8)
    info = js.consumer_info("PAUSE", "c")
    expect(info.paused).to be(true)
    expect(info.pause_remaining).to be_between(0.0, 0.8).exclusive
  end

  it "decodes the nanoseconds of the server exactly" do
    js.pause_consumer("PAUSE", "c", Time.now + 30)
    raw = JSON.parse(nc.request("$JS.API.CONSUMER.INFO.PAUSE.c", "", timeout: 2).data, symbolize_names: true)
    nanos = raw[:pause_remaining]
    expected = (nanos % 1_000_000_000).zero? ? nanos / 1_000_000_000 : nanos.fdiv(1_000_000_000)
    expect(NATS::JetStream::API::ConsumerInfo.new(raw).pause_remaining).to eql(expected)
  end

  it "is an Integer for whole seconds" do
    resp = NATS::JetStream::API::ConsumerPauseResponse.new(paused: true, pause_remaining: 59_000_000_000)
    expect(resp.pause_remaining).to eql(59)
    resp = NATS::JetStream::API::ConsumerPauseResponse.new(paused: true, pause_remaining: 59_250_000_000)
    expect(resp.pause_remaining).to eql(59.25)
    resp = NATS::JetStream::API::ConsumerPauseResponse.new(paused: true, pause_remaining: 1)
    expect(resp.pause_remaining).to eql(1.0e-09)
    expect(NATS::JetStream::API::ConsumerPauseResponse.new(paused: false).pause_remaining).to be_nil
  end

  it "is nil once the consumer resumes" do
    js.pause_consumer("PAUSE", "c", Time.now + 60)
    expect(js.resume_consumer("PAUSE", "c").pause_remaining).to be_nil
    expect(js.consumer_info("PAUSE", "c").pause_remaining).to be_nil
  end
end

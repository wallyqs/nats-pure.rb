# frozen_string_literal: true

describe "JetStream opt_start_time readers" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-start-time")
    @s = NatsServerControl.new("nats://127.0.0.1:4738", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:start) { Time.at(1_700_000_000, 123_456_789, :nsec).utc }

  before { js.add_stream(name: "ORIGIN", subjects: ["origin"]) }

  after { nc.close }

  it "reads the opt_start_time of a fetched consumer config as a Time" do
    js.add_consumer("ORIGIN", durable_name: "c", deliver_policy: "by_start_time", opt_start_time: start)

    config = js.consumer_info("ORIGIN", "c").config
    expect(config.opt_start_time).to be_a(String)
    expect(config.start_time).to eql(start)
    expect(js.consumer_info("ORIGIN", "c").config.start_time.nsec).to eql(123_456_789)
  end

  it "reads the opt_start_time of a config given as a Time or a String" do
    expect(NATS::JetStream::API::ConsumerConfig.new(opt_start_time: start).start_time).to eql(start)
    expect(NATS::JetStream::API::ConsumerConfig.new(opt_start_time: "2023-11-14T22:13:20.123456789Z").start_time).to eql(start)
    expect(NATS::JetStream::API::ConsumerConfig.new.start_time).to be_nil
  end

  it "reads the opt_start_time of the fetched mirror and sources of a stream as a Time" do
    js.add_stream(name: "MIRROR", mirror: {name: "ORIGIN", opt_start_time: start})
    js.add_stream(name: "OTHER", subjects: ["other"])
    created = js.add_stream(name: "SOURCED", sources: [{name: "ORIGIN", opt_start_time: start}, {name: "OTHER"}])

    mirror = js.stream_info("MIRROR").config.mirror
    expect(mirror).to be_a(NATS::JetStream::API::StreamSource)
    expect(mirror[:name]).to eql("ORIGIN")
    expect(mirror[:opt_start_time]).to be_a(String)
    expect(mirror.start_time).to eql(start)

    sources = js.stream_info("SOURCED").config.sources
    expect(sources.map(&:start_time)).to eql([start, nil])
    expect(created.config.sources.first.start_time).to eql(start)
  end

  it "updates a stream with a fetched config" do
    js.add_stream(name: "SOURCED", sources: [{name: "ORIGIN", opt_start_time: start}])
    config = js.stream_info("SOURCED").config
    config.description = "updated"

    updated = js.update_stream(config)
    expect(updated.config.description).to eql("updated")
    expect(updated.config.sources.first.start_time).to eql(start)
  end
end

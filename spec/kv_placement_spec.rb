# frozen_string_literal: true

describe "KeyValue placement" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-kv-placement")
    @s = NatsServerControl.new("nats://127.0.0.1:4622", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir} -n kv-placement")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  it "creates the bucket's stream with the placement" do
    kv = js.create_key_value(bucket: "PLACED", placement: {tags: ["ssd", "east"]})
    placement = kv.status.stream_info.config.placement
    expect(placement).to eql({tags: ["ssd", "east"]})
  end

  it "takes the placement of a KeyValueConfig" do
    config = NATS::KeyValue::API::KeyValueConfig.new(bucket: "PLACED", placement: {tags: ["ssd"]})
    js.create_key_value(config)
    expect(js.stream_info("KV_PLACED").config.placement).to eql({tags: ["ssd"]})
  end

  it "creates the bucket without a placement by default" do
    js.create_key_value(bucket: "UNPLACED")
    expect(js.stream_info("KV_UNPLACED").config.placement).to be_nil
  end
end

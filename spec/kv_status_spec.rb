# frozen_string_literal: true

describe "KeyValue handle and bucket status" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-kv-status")
    @s = NatsServerControl.new("nats://127.0.0.1:4637", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  it "names the bucket of a handle, like Bucket" do
    expect(js.create_key_value(bucket: "TEST").bucket).to eql("TEST")
    expect(js.key_value("TEST").bucket).to eql("TEST")
    expect(js.create_key_value(bucket: "MIRROR", mirror: {name: "TEST"}).bucket).to eql("MIRROR")
  end

  it "reports the backing store and the bytes, like BackingStore and Bytes" do
    kv = js.create_key_value(bucket: "TEST")
    status = kv.status
    expect(status.backing_store).to eql("JetStream")
    expect(status.bytes).to eql(0)

    kv.put("a", "1")
    kv.put("b", "22")
    status = kv.status
    expect(status.bytes).to be > 0
    expect(status.bytes).to eql(js.stream_info("KV_TEST").state.bytes)
    expect(js.key_value_stores.first.bytes).to eql(status.bytes)
  end

  it "rebuilds the config of the bucket, like Config" do
    kv = js.create_key_value(
      bucket: "CONF",
      description: "a bucket",
      max_value_size: 128,
      history: 5,
      ttl: 3600,
      max_bytes: 4096,
      storage: "memory",
      direct: true,
      compression: false,
      metadata: {"owner" => "test"},
      republish: {src: ">", dest: "repub.>"}
    )
    config = kv.status.config
    expect(config).to be_a NATS::KeyValue::API::KeyValueConfig
    expect(config.bucket).to eql("CONF")
    expect(config.description).to eql("a bucket")
    expect(config.max_value_size).to eql(128)
    expect(config.history).to eql(5)
    expect(config.ttl).to eql(3600)
    expect(config.max_bytes).to eql(4096)
    expect(config.storage).to eql("memory")
    expect(config.replicas).to eql(1)
    expect(config.direct).to be(true)
    expect(config.compression).to be(false)
    expect(config.metadata[:owner]).to eql("test")
    expect(config.republish).to include(src: ">", dest: "repub.>")
    expect(config.limit_marker_ttl).to eql(0)
    expect(config.mirror).to be_nil
    expect(config.sources).to be_nil
  end

  it "rebuilds the defaults, compression, limit markers, mirrors and sources" do
    config = js.create_key_value(bucket: "DEF").status.config
    expect(config.history).to eql(1)
    expect(config.ttl).to eql(0)
    expect(config.max_value_size).to eql(-1)
    expect(config.max_bytes).to eql(-1)
    expect(config.storage).to eql("file")

    config = js.create_key_value(bucket: "S2", compression: true, limit_marker_ttl: 5).status.config
    expect(config.compression).to be(true)
    expect(config.limit_marker_ttl).to eql(5)

    config = js.create_key_value(bucket: "MIRROR", mirror: {name: "DEF"}).status.config
    expect(config.mirror[:name]).to eql("KV_DEF")

    config = js.create_key_value(bucket: "SRC", sources: [{name: "DEF"}]).status.config
    expect(config.sources.map { |source| source[:name] }).to eql(["KV_DEF"])
  end

  it "takes the config again to create the same bucket" do
    kv = js.create_key_value(bucket: "AGAIN", history: 3, ttl: 60, description: "again")
    kv.put("k", "v")
    again = js.create_key_value(kv.status.config)
    expect(again.get("k").value).to eql("v")
    expect(again.status.history).to eql(3)
  end
end

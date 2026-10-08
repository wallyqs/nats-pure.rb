# frozen_string_literal: true

describe "KeyValue get delta" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-kv-get-delta")
    @s = NatsServerControl.new("nats://127.0.0.1:4741", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  [true, false].each do |direct|
    it "reports a delta of 0, like nats.go, with direct #{direct}" do
      kv = js.create_key_value(bucket: "DELTA", history: 5, direct: direct)
      3.times { |i| kv.put("k", i.to_s) }
      kv.put("other", "x")

      entry = kv.get("k")
      expect(entry.value).to eql("2")
      expect(entry.delta).to eql(0)
      expect(kv.get("k", revision: 1).delta).to eql(0)
    end
  end
end

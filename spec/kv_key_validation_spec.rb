# frozen_string_literal: true

describe "KeyValue key validation" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-kv-key-validation")
    @s = NatsServerControl.new("nats://127.0.0.1:4739", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:kv) { js.create_key_value(bucket: "KEYS", history: 5) }
  # The keys that keyValid of nats.go refuses, and some that the pattern
  # of a valid key with a trailing newline let through.
  let(:bad_keys) { ["", nil, ".foo", "foo.", "foo..bar", "foo bar", "foo+bar", "foo*", "foo.>", ">", "foo\nbar", "foo\n"] }
  # The patterns of keys that searchKeyValid of nats.go refuses.
  let(:bad_patterns) { ["", ".foo", "foo.", "foo..bar", "foo bar", "foo+bar", "foo.>.bar", "foo\n"] }

  after { nc.close }

  def expect_invalid(&block)
    expect(&block).to raise_error(NATS::KeyValue::InvalidKeyError, "nats: invalid key")
  end

  it "refuses invalid keys by default, before sending anything" do
    sent = nc.subscribe("$KV.KEYS.>")
    nc.flush
    bad_keys.each do |key|
      expect_invalid { kv.put(key, "v") }
      expect_invalid { kv.get(key) }
      expect_invalid { kv.get(key, revision: 1) }
      expect_invalid { kv.create(key, "v") }
      expect_invalid { kv.update(key, "v", last: 1) }
      expect_invalid { kv.delete(key) }
      expect_invalid { kv.purge(key) }
    end
    nc.flush
    expect(sent.pending_queue.size).to eql(0)
  end

  it "takes valid keys, also as Symbols and Integers" do
    %w[foo foo.bar a/b=c-d_e.F9 _ 1].each do |key|
      kv.put(key, "v")
      expect(kv.get(key).value).to eql("v")
    end
    kv.put(:sym, "s")
    expect(kv.get("sym").value).to eql("s")
    kv.put(42, "n")
    expect(kv.get(42).value).to eql("n")
  end

  it "takes patterns with wildcards in watch, list_keys_filtered and history" do
    kv.put("a.b", "1")
    kv.put("a.c.d", "2")

    expect(kv.list_keys_filtered("a.*").to_a).to eql(["a.b"])
    expect(kv.list_keys_filtered("a.>").to_a.sort).to eql(["a.b", "a.c.d"])
    expect(kv.list_keys_filtered("*.c.*", "a.b").to_a.sort).to eql(["a.b", "a.c.d"])
    expect(kv.keys("a.*.d").to_a).to eql(["a.c.d"])
    expect(kv.history("a.*").map(&:key)).to eql(["a.b"])
    w = kv.watch("a.>")
    expect(w.updates(timeout: 1).key).to eql("a.b")
    w.stop
  end

  it "refuses invalid patterns in watch, list_keys_filtered and history" do
    bad_patterns.each do |pattern|
      expect_invalid { kv.watch(pattern) }
      expect_invalid { kv.watch(["a.*", pattern]) }
      expect_invalid { kv.list_keys_filtered("a.*", pattern) }
      expect_invalid { kv.history(pattern) }
    end
  end

  it "leaves keys unchecked with validate_keys: false" do
    unchecked = js.create_key_value(bucket: "RAW", validate_keys: false)
    unchecked.put("foo+bar", "1")
    expect(unchecked.get("foo+bar").value).to eql("1")
    expect(unchecked.list_keys_filtered("foo+bar").to_a).to eql(["foo+bar"])

    bound = js.key_value("RAW", validate_keys: false)
    expect(bound.get("foo+bar").value).to eql("1")
    expect_invalid { js.key_value("RAW").get("foo+bar") }
  end
end

# frozen_string_literal: true

describe "KeyValue key listing" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-kv-list-keys")
    @s = NatsServerControl.new("nats://127.0.0.1:4636", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:kv) { js.create_key_value(bucket: "KEYS", history: 3) }

  after { nc.close }

  # The subscriptions of the connection once the bucket exists, to check
  # that listings stop their watchers.
  def baseline
    kv.status
    nc.num_subscriptions
  end

  describe "list_keys" do
    it "lists no keys of an empty bucket, and stops" do
      subs = baseline
      lister = kv.list_keys
      expect(lister).to be_a NATS::KeyLister
      expect(lister.to_a).to eql([])
      expect(lister.stopped?).to be(true)
      expect(nc.num_subscriptions).to eql(subs)
    end

    it "lists the keys that are not deleted or purged, like ListKeys" do
      kv.put("a", "1")
      kv.put("b", "2")
      kv.put("a", "11")
      kv.put("c", "3")
      kv.delete("b")
      kv.purge("c")

      subs = baseline
      expect(kv.list_keys.to_a).to eql(["a"])
      lister = kv.list_keys
      expect(lister.keys.to_a).to eql(["a"])
      expect(nc.num_subscriptions).to eql(subs)
    end

    it "stops its watcher when the listing is left early" do
      300.times { |i| kv.put("k#{i}", "v") }
      subs = baseline

      lister = kv.list_keys
      expect(lister.first(2)).to eql(%w[k0 k1])
      expect(lister.stopped?).to be(true)
      expect(nc.num_subscriptions).to eql(subs)

      lister = kv.list_keys
      lister.each { |key| break if key == "k10" }
      expect(lister.stopped?).to be(true)
      expect(nc.num_subscriptions).to eql(subs)
    end

    it "stops from another thread, ending the listing" do
      subs = baseline
      lister = kv.list_keys(updates_only: true)
      listed = Queue.new
      t = Thread.new { lister.each { |key| listed << key } }

      kv.put("late", "1")
      expect(listed.pop(timeout: 5)).to eql("late")
      lister.stop
      expect(t.join(5)).to be_truthy
      expect(nc.num_subscriptions).to eql(subs)
    end

    it "stops a listing that was never read" do
      kv.put("a", "1")
      subs = baseline
      lister = kv.list_keys
      expect(nc.num_subscriptions).to eql(subs + 1)
      lister.stop
      lister.stop
      expect(nc.num_subscriptions).to eql(subs)
      expect(lister.to_a).to eql([])
    end
  end

  describe "list_keys_filtered" do
    before do
      kv.put("a.1", "1")
      kv.put("a.2", "2")
      kv.put("b.1", "3")
      kv.put("c", "4")
      kv.delete("a.2")
    end

    it "lists the keys that match any of the filters, like ListKeysFiltered" do
      expect(kv.list_keys_filtered("a.*").to_a).to eql(["a.1"])
      expect(kv.list_keys_filtered("a.*", "c").to_a.sort).to eql(%w[a.1 c])
      expect(kv.list_keys_filtered(["b.>", "c"]).to_a.sort).to eql(%w[b.1 c])
      expect(kv.list_keys_filtered("none.*").to_a).to eql([])
    end

    it "lists all keys without filters" do
      expect(kv.list_keys_filtered.to_a.sort).to eql(%w[a.1 b.1 c])
    end
  end

  describe "keys" do
    it "still raises NoKeysFoundError on an empty bucket, like Keys, and stops" do
      subs = baseline
      expect { kv.keys.to_a }.to raise_error(NATS::KeyValue::NoKeysFoundError)
      expect(nc.num_subscriptions).to eql(subs)
    end

    it "honors filters, given as such or as :filters" do
      kv.put("a.1", "1")
      kv.put("a.2", "2")
      kv.put("b.1", "3")
      kv.put("c", "4")

      expect(kv.keys("a.*").to_a).to eql(%w[a.1 a.2])
      expect(kv.keys(["a.1", "c"]).to_a.sort).to eql(%w[a.1 c])
      expect(kv.keys(filters: ["b.*"]).to_a).to eql(["b.1"])
      expect(kv.keys.to_a.sort).to eql(%w[a.1 a.2 b.1 c])
      expect { kv.keys("none").to_a }.to raise_error(NATS::KeyValue::NoKeysFoundError)
    end

    it "yields to a block, and stops its watcher when left early" do
      20.times { |i| kv.put("k#{i}", "v") }
      subs = baseline

      keys = []
      kv.keys { |key| keys << key }
      expect(keys.size).to eql(20)
      expect(nc.num_subscriptions).to eql(subs)

      expect(kv.keys.take(1)).to eql(["k0"])
      expect(nc.num_subscriptions).to eql(subs)
      kv.keys.each { |key| break if key == "k3" }
      expect(nc.num_subscriptions).to eql(subs)
    end
  end
end

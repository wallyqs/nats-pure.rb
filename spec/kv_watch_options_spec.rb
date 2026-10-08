# frozen_string_literal: true

describe "KeyValue watch options" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-kv-watch-options")
    @s = NatsServerControl.new("nats://127.0.0.1:4626", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:kv) { js.create_key_value(bucket: "WATCH", history: 10) }

  after { nc.close }

  # Takes the updates until the nil that ends the initial ones.
  def initial_entries(w)
    entries = []
    while (entry = w.updates)
      entries << entry
    end
    entries
  end

  def expect_no_updates(w)
    sleep 0.3
    expect(w._updates.size).to eql(0)
  end

  # Deletes the consumer of the watcher, as a server restart does, and waits
  # for the watcher to notice the missing heartbeats and recreate it.
  def recreate_consumer(w)
    consumer = w._sub.jsi.consumer
    js.delete_consumer(w._sub.jsi.stream, consumer)
    wait_until(description: "the consumer to be recreated") { w._sub.jsi.consumer != consumer }
  end

  before do
    kv.put("a", "a1") # 1
    kv.put("b", "b1") # 2
    kv.put("a", "a2") # 3
    kv.put("c", "c1") # 4
  end

  describe "updates_only" do
    it "delivers only the updates made after the watch starts, with no nil update" do
      w = kv.watchall(updates_only: true)
      expect_no_updates(w)

      kv.put("b", "b2")
      kv.delete("c")
      entry = w.updates
      expect([entry.key, entry.value, entry.revision]).to eql(["b", "b2", 5])
      entry = w.updates
      expect([entry.key, entry.operation, entry.revision]).to eql(["c", "DEL", 6])
      expect_no_updates(w)
      w.stop
    end

    it "watches only the given keys" do
      w = kv.watch("a", updates_only: true)
      kv.put("b", "b2")
      kv.put("a", "a3")
      expect(w.updates.value).to eql("a3")
      w.stop
    end

    it "does not replay the earlier entries when the consumer is recreated" do
      w = kv.watchall(updates_only: true, idle_heartbeat: 1)
      recreate_consumer(w)
      kv.put("b", "b2")
      expect(w.updates.revision).to eql(5)
      expect_no_updates(w)
      w.stop
    end
  end

  describe "resume_from_revision" do
    it "delivers every entry from the revision on" do
      w = kv.watchall(resume_from_revision: 3)
      expect(initial_entries(w).map { |e| [e.key, e.revision] }).to eql([["a", 3], ["c", 4]])

      kv.put("b", "b2")
      expect(w.updates.revision).to eql(5)
      w.stop
    end

    it "watches only the given keys" do
      w = kv.watch("a", resume_from_revision: 2)
      expect(initial_entries(w).map(&:value)).to eql(["a2"])
      w.stop
    end

    it "ends the initial entries at once when resuming from the next revision" do
      w = kv.watchall(resume_from_revision: 5)
      expect(w.updates).to be_nil
      kv.put("b", "b2")
      expect(w.updates.revision).to eql(5)
      w.stop
    end

    it "comes before updates_only" do
      w = kv.watchall(resume_from_revision: 4, updates_only: true)
      expect(initial_entries(w).map(&:revision)).to eql([4])
      w.stop
    end

    it "resumes from the revision when the consumer is recreated before an entry" do
      w = kv.watch("b", resume_from_revision: 3, idle_heartbeat: 1)
      expect(w.updates).to be_nil
      recreate_consumer(w)
      kv.put("b", "b2")
      expect(w.updates.revision).to eql(5)
      expect_no_updates(w)
      w.stop
    end
  end
end

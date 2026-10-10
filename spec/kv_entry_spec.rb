# frozen_string_literal: true

describe "KeyValue entries" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-kv-entry")
    @s = NatsServerControl.new("nats://127.0.0.1:4635", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  it "has the operation constants of nats.go, as the Strings of the operations" do
    expect(NATS::KeyValue::Operation::PUT).to eql("PUT")
    expect(NATS::KeyValue::Operation::DELETE).to eql("DEL")
    expect(NATS::KeyValue::Operation::PURGE).to eql("PURGE")
    expect(NATS::KeyValue::KV_PUT).to eql(NATS::KeyValue::Operation::PUT)
    expect(NATS::KeyValue::KV_DEL).to eql(NATS::KeyValue::Operation::DELETE)
    expect(NATS::KeyValue::KV_PURGE).to eql(NATS::KeyValue::Operation::PURGE)
    expect(NATS::KeyValue::ALL_KEYS).to eql(">")
    expect(NATS::KeyValue::KEY_VALUE_MAX_HISTORY).to eql(64)
  end

  [false, true].each do |direct|
    context(direct ? "with direct gets" : "with stream message gets") do
      it "gets entries with the time they were stored and the put operation" do
        kv = js.create_key_value(bucket: "ENTRY", history: 5, direct: direct)
        before = Time.now
        kv.put("a", "1")
        kv.put("a", "2")
        after = Time.now

        entry = kv.get("a")
        expect(entry.value).to eql("2")
        expect(entry.revision).to eql(2)
        expect(entry.operation).to eql(NATS::KeyValue::Operation::PUT)
        expect(entry.created).to be_a(Time)
        expect(entry.created).to be_between(before - 1, after + 1)

        first = kv.get("a", revision: 1)
        expect(first.value).to eql("1")
        expect(first.revision).to eql(1)
        expect(first.operation).to eql("PUT")
        expect(first.created).to be <= entry.created

        # The time is that of the message in the stream, to the nanosecond.
        msg = js.get_msg("KV_ENTRY", seq: 2)
        expect(entry.created).to eql(msg.time)
        history = kv.history("a").to_a
        expect(history.map(&:created)).to eql([first.created, entry.created])
      end
    end
  end

  it "watches entries with the put, delete and purge operations" do
    kv = js.create_key_value(bucket: "OPS", history: 5)
    w = kv.watchall
    expect(w.updates).to be_nil

    kv.put("a", "1")
    kv.delete("a")
    kv.put("b", "2")
    kv.purge("b")
    ops = 4.times.map { w.updates }.map { |e| [e.key, e.operation] }
    expect(ops).to eql([
      ["a", NATS::KeyValue::Operation::PUT],
      ["a", NATS::KeyValue::Operation::DELETE],
      ["b", NATS::KeyValue::Operation::PUT],
      ["b", NATS::KeyValue::Operation::PURGE]
    ])
    w.stop

    expect(kv.history("a").map(&:operation)).to eql(%w[PUT DEL])
  end

  it "limits the history to KEY_VALUE_MAX_HISTORY" do
    kv = js.create_key_value(bucket: "MAXH", history: NATS::KeyValue::KEY_VALUE_MAX_HISTORY)
    expect(kv.status.history).to eql(64)
    expect do
      js.create_key_value(bucket: "TOOMUCH", history: NATS::KeyValue::KEY_VALUE_MAX_HISTORY + 1)
    end.to raise_error(NATS::KeyValue::KeyHistoryTooLargeError, "nats: history limited to a max of 64")
  end
end

# frozen_string_literal: true

describe "KeyValue purge_deletes" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-kv-purge-deletes")
    @s = NatsServerControl.new("nats://127.0.0.1:4625", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:kv) { js.create_key_value(bucket: "PD", history: 10) }

  after { nc.close }

  def subject_count(key)
    kv.history(key).count
  rescue NATS::KeyValue::NoKeysFoundError
    0
  end

  def stream_messages
    js.stream_info("KV_PD").state.messages
  end

  before do
    kv.put("deleted", "1")
    kv.put("deleted", "2")
    kv.delete("deleted")
    kv.put("purged", "1")
    kv.purge("purged")
    kv.put("kept", "1")
    kv.put("kept", "2")
  end

  it "keeps recent markers, but removes the data of their keys, by default" do
    expect(stream_messages).to eql(6)

    expect(kv.purge_deletes).to be_nil

    expect(subject_count("deleted")).to eql(1)
    expect(subject_count("purged")).to eql(1)
    expect(subject_count("kept")).to eql(2)
    expect(kv.history("deleted").map(&:operation)).to eql(["DEL"])
    expect(stream_messages).to eql(4)
  end

  it "removes all markers when older_than is negative" do
    kv.purge_deletes(older_than: -1)

    expect(subject_count("deleted")).to eql(0)
    expect(subject_count("purged")).to eql(0)
    expect(subject_count("kept")).to eql(2)
    expect(kv.keys.to_a).to eql(["kept"])
    expect(stream_messages).to eql(2)
  end

  it "removes the markers older than older_than" do
    sleep 1.5
    kv.delete("kept")

    kv.purge_deletes(older_than: 1)

    expect(subject_count("deleted")).to eql(0)
    expect(subject_count("purged")).to eql(0)
    # The marker of the recent delete stays.
    expect(kv.history("kept").map(&:operation)).to eql(["DEL"])
    expect(stream_messages).to eql(1)
  end

  it "does nothing without deleted keys" do
    js.delete_key_value("PD")
    empty = js.create_key_value(bucket: "EMPTY")
    empty.put("a", "1")
    expect(empty.purge_deletes(older_than: -1)).to be_nil
    expect(empty.get("a").value).to eql("1")

    js.create_key_value(bucket: "NONE").purge_deletes
  end
end

# frozen_string_literal: true

describe "KeyValue purge and delete of a last revision" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-kv-purge-options")
    @s = NatsServerControl.new("nats://127.0.0.1:4638", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:kv) { js.create_key_value(bucket: "PURGE", history: 5) }

  after { nc.close }

  it "purges only the latest revision given as :last, like LastRevision" do
    kv.put("k", "1")
    rev = kv.put("k", "2")

    expect do
      kv.purge("k", last: rev - 1)
    end.to raise_error(NATS::JetStream::Error::WrongLastSequence)
    expect(kv.get("k").value).to eql("2")
    expect(kv.history("k").count).to eql(2)

    ack = kv.purge("k", last: rev)
    expect(ack).to be_a NATS::JetStream::PubAck
    expect(ack.seq).to eql(rev + 1)
    expect { kv.get("k") }.to raise_error(NATS::KeyValue::KeyNotFoundError)
    expect(kv.history("k").map(&:operation)).to eql(["PURGE"])
  end

  it "purges whatever the latest revision without :last, or with 0" do
    kv.put("k", "1")
    kv.put("k", "2")
    expect(kv.purge("k", last: 0).seq).to eql(3)
    kv.put("k", "3")
    expect(kv.purge("k").seq).to eql(5)
    expect(kv.history("k").map(&:operation)).to eql(["PURGE"])
  end

  it "deletes only the latest revision given as :last, as purge does" do
    kv.put("k", "1")
    rev = kv.put("k", "2")

    expect do
      kv.delete("k", last: rev - 1)
    end.to raise_error(NATS::JetStream::Error::WrongLastSequence)
    expect(kv.get("k").value).to eql("2")

    expect(kv.delete("k", last: rev)).to eql(rev + 1)
    expect(kv.history("k").map(&:operation)).to eql(%w[PUT PUT DEL])
  end

  it "takes :last together with a TTL of the purge marker" do
    kv = js.create_key_value(bucket: "PTTL", limit_marker_ttl: 60)
    rev = kv.put("k", "1")
    expect { kv.purge("k", last: rev + 5, ttl: 30) }.to raise_error(NATS::JetStream::Error::WrongLastSequence)
    expect(kv.purge("k", last: rev, ttl: 30).seq).to eql(rev + 1)
  end
end

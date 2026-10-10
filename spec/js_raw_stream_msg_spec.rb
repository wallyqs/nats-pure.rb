# frozen_string_literal: true

describe "JetStream raw stream messages" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-raw-msg")
    @s = NatsServerControl.new("nats://127.0.0.1:4763", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  before do
    js.add_stream(name: "RAW", subjects: ["raw.>"], allow_direct: true)
    js.publish("raw.a", "one", header: {"X" => ["1", "2"], "Y" => "3"})
    js.publish("raw.b", "two")
  end

  # The times at which the server stored the messages, from their metadata.
  def stored_times
    psub = js.pull_subscribe("raw.>", "c")
    psub.fetch(2).map { |msg| msg.metadata.timestamp }
  end

  [false, true].each do |direct|
    context(direct ? "with a direct get" : "with a get") do
      it "has the sequence as an Integer, and the time of the message" do
        times = stored_times

        msg = js.get_msg("RAW", seq: 1, direct: direct)
        expect(msg.seq).to eql(1)
        expect(msg.sequence).to eql(1)
        expect(msg.subject).to eql("raw.a")
        expect(msg.data).to eql("one")
        expect(msg.time).to be_a(Time)
        expect(msg.time).to eql(times[0])

        msg = js.get_last_msg("RAW", "raw.b", direct: direct)
        expect(msg.seq).to eql(2)
        expect(msg.time).to eql(times[1])
      end

      it "keeps the values of repeated header names" do
        msg = js.get_msg("RAW", seq: 1, direct: direct)
        expect(msg.headers["X"]).to eql(["1", "2"])
        expect(msg.headers["Y"]).to eql("3")
      end
    end
  end

  it "gives the entries of a KV bucket read with direct gets Integer revisions" do
    kv = js.create_key_value(bucket: "RAWKV", history: 2, direct: true)
    kv.put("k", "v")
    kv.put("k", "w")

    expect(kv.get("k").revision).to eql(2)
    expect(kv.get("k", revision: 1).revision).to eql(1)
  end
end

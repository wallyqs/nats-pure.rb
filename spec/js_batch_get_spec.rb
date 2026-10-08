# frozen_string_literal: true

describe "JetStream batch direct get" do
  before(:all) do
    @tmpdir = Dir.mktmpdir("ruby-jetstream")
    @s = NatsServerControl.new("nats://127.0.0.1:4886", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:errors) { NATS::JetStream::Error }

  before do
    js.add_stream(name: "BG", subjects: ["bg.>"], allow_direct: true)
    # bg.a: 1, 3, 5, 7, 9; bg.b: 2, 4, 6, 8, 10.
    (1..10).each { |i| js.publish(i.odd? ? "bg.a" : "bg.b", "m#{i}") }
  end

  after do
    js.delete_stream("BG")
    nc.close
  end

  describe "get_batch" do
    it "gets messages from the first one of the stream" do
      msgs = js.get_batch("BG", 4)

      expect(msgs.map(&:seq)).to eql([1, 2, 3, 4])
      expect(msgs.map(&:data)).to eql(%w[m1 m2 m3 m4])
      expect(msgs.map(&:subject)).to eql(%w[bg.a bg.b bg.a bg.b])
      expect(msgs.first).to be_a(NATS::JetStream::API::RawStreamMsg)
      expect(msgs.first.headers).to include(
        "Nats-Stream" => "BG", "Nats-Sequence" => "1", "Nats-Num-Pending" => "9", "Nats-Last-Sequence" => "0"
      )
      expect(msgs.first.headers["Nats-Time-Stamp"]).not_to be_nil
    end

    it "gets messages from a sequence, on a subject" do
      expect(js.get_batch("BG", 3, seq: 4).map(&:seq)).to eql([4, 5, 6])
      expect(js.get_batch("BG", 3, subject: "bg.b").map(&:seq)).to eql([2, 4, 6])
      expect(js.get_batch("BG", 10, seq: 5, subject: "bg.>").map(&:seq)).to eql([5, 6, 7, 8, 9, 10])
    end

    it "stops at the end of the stream" do
      expect(js.get_batch("BG", 100, seq: 8).map(&:seq)).to eql([8, 9, 10])
    end

    it "gets messages from a start time" do
      sleep 0.05
      start = Time.now
      sleep 0.05
      js.publish("bg.a", "later")

      msgs = js.get_batch("BG", 5, start_time: start)
      expect(msgs.map(&:data)).to eql(["later"])
      expect(js.get_batch("BG", 5, start_time: start.utc.iso8601(9)).map(&:seq)).to eql([11])
    end

    it "stops once the messages reach max_bytes" do
      # Each message counts its subject and data: 4 + 2 bytes.
      expect(js.get_batch("BG", 10, max_bytes: 13).map(&:seq)).to eql([1, 2, 3])
    end

    it "yields the messages to a block" do
      seen = []
      expect(js.get_batch("BG", 3) { |msg| seen << msg.seq }).to be_nil
      expect(seen).to eql([1, 2, 3])

      first = nil
      js.get_batch("BG", 10) do |msg|
        first = msg
        break
      end
      expect(first.seq).to eql(1)
      expect(js.get_batch("BG", 2).map(&:seq)).to eql([1, 2])
    end

    it "raises NoMessages when there are none" do
      expect { js.get_batch("BG", 5, seq: 11) }.to raise_error(errors::NoMessages, "nats: no messages")
      expect { js.get_batch("BG", 5, subject: "bg.none") }.to raise_error(errors::NoMessages)
    end

    it "raises ServiceUnavailable for a stream without allow_direct" do
      js.add_stream(name: "NODIRECT", subjects: ["nd"])
      js.publish("nd", "x")

      expect { js.get_batch("NODIRECT", 1) }.to raise_error(errors::ServiceUnavailable)
    ensure
      js.delete_stream("NODIRECT")
    end

    it "raises ArgumentError for invalid options, before sending" do
      expect { js.get_batch("BG", 0) }.to raise_error(ArgumentError, /batch/)
      expect { js.get_batch("BG", 1, seq: 0) }.to raise_error(ArgumentError, /seq/)
      expect { js.get_batch("BG", 1, seq: 1, start_time: Time.now) }.to raise_error(ArgumentError, /start time and sequence/)
      expect { js.get_batch("BG", 1, max_bytes: 0) }.to raise_error(ArgumentError, /max_bytes/)
      expect { js.get_batch("", 1) }.to raise_error(errors::InvalidStreamName)
    end
  end

  describe "get_last_msgs_for" do
    it "gets the last message on each subject, in the order of the stream" do
      msgs = js.get_last_msgs_for("BG", ["bg.b", "bg.a"])

      expect(msgs.map(&:seq)).to eql([9, 10])
      expect(msgs.map(&:subject)).to eql(%w[bg.a bg.b])
      expect(msgs.map(&:data)).to eql(%w[m9 m10])
    end

    it "takes wildcards and a single subject" do
      expect(js.get_last_msgs_for("BG", "bg.>").map(&:seq)).to eql([9, 10])
      expect(js.get_last_msgs_for("BG", "bg.a").map(&:seq)).to eql([9])
    end

    it "looks up to a sequence or a time" do
      expect(js.get_last_msgs_for("BG", ["bg.a", "bg.b"], up_to_seq: 4).map(&:seq)).to eql([3, 4])

      sleep 0.05
      before = Time.now
      sleep 0.05
      js.publish("bg.a", "later")
      expect(js.get_last_msgs_for("BG", ["bg.a", "bg.b"]).map(&:seq)).to eql([10, 11])
      expect(js.get_last_msgs_for("BG", ["bg.a", "bg.b"], up_to_time: before).map(&:seq)).to eql([9, 10])
    end

    it "gets at most batch messages" do
      expect(js.get_last_msgs_for("BG", ["bg.a", "bg.b"], batch: 1).map(&:seq)).to eql([9])
    end

    it "yields the messages to a block" do
      seen = []
      expect(js.get_last_msgs_for("BG", ["bg.a", "bg.b"]) { |msg| seen << msg.data }).to be_nil
      expect(seen).to eql(%w[m9 m10])
    end

    it "raises NoMessages when there are none" do
      expect { js.get_last_msgs_for("BG", ["bg.none"]) }.to raise_error(errors::NoMessages)
      expect { js.get_last_msgs_for("BG", ["bg.a"], up_to_time: Time.now - 3600) }.to raise_error(errors::NoMessages)
    end

    it "raises ArgumentError without subjects or for invalid options" do
      expect { js.get_last_msgs_for("BG", []) }.to raise_error(ArgumentError, "nats: at least one subject is required")
      expect { js.get_last_msgs_for("BG", [""]) }.to raise_error(ArgumentError)
      expect { js.get_last_msgs_for("BG", ["bg.a"], batch: 0) }.to raise_error(ArgumentError, /batch/)
      expect { js.get_last_msgs_for("BG", ["bg.a"], up_to_seq: -1) }.to raise_error(ArgumentError, /up_to_seq/)
      expect do
        js.get_last_msgs_for("BG", ["bg.a"], up_to_seq: 1, up_to_time: Time.now)
      end.to raise_error(ArgumentError, /up to sequence and up to time/)
    end
  end

  describe "responses that are not batches" do
    # A responder in place of a stream, as a server that does not get
    # messages in batches, or that sends what it should not.
    def respond_with(header, data = "x")
      nc.subscribe("$JS.API.DIRECT.GET.FAKE") do |msg|
        nc.publish_msg(NATS::Msg.new(subject: msg.reply, data: data, header: header))
      end
      nc.flush
    end

    let(:batch_header) do
      {"Nats-Stream" => "FAKE", "Nats-Subject" => "fake", "Nats-Sequence" => "1",
       "Nats-Time-Stamp" => "2026-01-01T00:00:00.123456789Z", "Nats-Num-Pending" => "0"}
    end

    it "raises BatchUnsupported for a message without Nats-Num-Pending" do
      respond_with(batch_header.except("Nats-Num-Pending"))

      expect { js.get_batch("FAKE", 2) }.to raise_error(errors::BatchUnsupported, "nats: batch get not supported by server")
    end

    it "raises InvalidStreamResponse for a message without the headers of a stream" do
      respond_with(batch_header.except("Nats-Sequence"))
      expect { js.get_batch("FAKE", 2) }.to raise_error(errors::InvalidStreamResponse, /missing sequence header/)
    end

    it "raises InvalidStreamResponse for an invalid sequence or time stamp" do
      respond_with(batch_header.merge("Nats-Time-Stamp" => "yesterday"))
      expect { js.get_batch("FAKE", 2) }.to raise_error(errors::InvalidStreamResponse, /invalid timestamp/)
    end

    it "raises NATS::Timeout when the batch does not end" do
      respond_with(batch_header)

      expect { js.get_batch("FAKE", 2, timeout: 0.3) }.to raise_error(NATS::Timeout)
    end

    it "raises the error of a status the server refuses the request with" do
      respond_with({"Status" => "408", "Description" => "Bad Request"}, "")

      expect { js.get_batch("FAKE", 2) }.to raise_error(NATS::JetStream::Error::APIError) do |e|
        expect(e.code).to eql("408")
      end
    end
  end
end

# frozen_string_literal: true

describe "JetStream atomic batch publishing" do
  before(:all) do
    @tmpdir = Dir.mktmpdir("ruby-jetstream")
    @s = NatsServerControl.new("nats://127.0.0.1:4862", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:hdr) { NATS::JetStream::Header }
  let(:errors) { NATS::JetStream::Error }

  before do
    js.add_stream(name: "BATCH", subjects: ["batch.>"], allow_atomic: true, allow_msg_ttl: true)
  end

  after do
    js.delete_stream("BATCH")
    begin
      js.delete_stream("PLAIN")
    rescue NATS::JetStream::Error::NotFound
      nil
    end
    nc.close
  end

  def messages
    js.stream_info("BATCH").state.messages
  end

  it "stores the batch only once it is committed" do
    batch = js.new_batch_publisher
    expect(batch.id).to match(/\A[A-Za-z0-9]{22}\z/)

    batch.add("batch.a", "one")
    batch.add("batch.b", "two", header: {"X-Mine" => "1"})
    expect(batch.size).to eql(2)
    expect(messages).to eql(0)

    ack = batch.commit("batch.c", "three")

    expect(ack).to be_a(NATS::JetStream::BatchAck)
    expect(ack).to have_attributes(stream: "BATCH", seq: 3, batch: batch.id, count: 3)
    expect(batch.closed?).to be(true)
    expect(batch.size).to eql(3)
    expect(messages).to eql(3)

    msg = js.get_msg("BATCH", seq: 2)
    expect(msg.data).to eql("two")
    expect(msg.headers).to include("X-Mine" => "1", hdr::BATCH_ID => batch.id, hdr::BATCH_SEQUENCE => "2")
    expect(js.get_msg("BATCH", seq: 3).headers).to include(hdr::BATCH_COMMIT => "1")
  end

  it "commits with an end-of-batch marker that is not stored" do
    batch = js.new_batch_publisher
    batch.add("batch.a", "one")
    batch.add("batch.b", "two")

    ack = batch.close

    expect(ack).to have_attributes(stream: "BATCH", seq: 2, batch: batch.id, count: 2)
    expect(messages).to eql(2)
    expect(batch.closed?).to be(true)
  end

  it "commits a message given as a NATS::Msg without changing it" do
    batch = js.new_batch_publisher
    first = NATS::Msg.new(subject: "batch.a", data: "one", header: {"X-A" => "a"})
    last = NATS::Msg.new(subject: "batch.b", data: "two")

    batch.add_msg(first)
    ack = batch.commit_msg(last)

    expect(ack.count).to eql(2)
    expect(first.header).to eql("X-A" => "a")
    expect(first.reply).to be_nil
    expect(last.header).to be_nil
  end

  it "refuses to be used once it is committed or discarded" do
    batch = js.new_batch_publisher
    batch.add("batch.a", "one")
    expect(batch.discard).to be_nil
    expect(batch.closed?).to be(true)

    expect { batch.add("batch.a") }.to raise_error(errors::BatchClosed, "nats: batch publisher closed")
    expect { batch.commit("batch.a") }.to raise_error(errors::BatchClosed)
    expect { batch.close }.to raise_error(errors::BatchClosed)
    expect { batch.discard }.to raise_error(errors::BatchClosed)
    expect(messages).to eql(0)

    committed = js.new_batch_publisher
    committed.commit("batch.a", "only")
    expect { committed.add("batch.a") }.to raise_error(errors::BatchClosed)
  end

  it "refuses to close an empty batch" do
    expect { js.new_batch_publisher.close }.to raise_error(errors::EmptyBatch, "nats: no messages in batch")
    expect { js.publish_msg_batch([]) }.to raise_error(errors::EmptyBatch)
  end

  it "publishes messages as a batch" do
    msgs = (1..5).map { |i| NATS::Msg.new(subject: "batch.#{i}", data: i.to_s) }
    msgs[2].header = {hdr::BATCH_COMMIT => "1"}

    ack = js.publish_msg_batch(msgs, ack_every: 2)

    expect(ack).to have_attributes(stream: "BATCH", seq: 5, count: 5)
    expect(messages).to eql(5)
    expect(msgs[2].header).to eql(hdr::BATCH_COMMIT => "1")
    expect(js.get_msg("BATCH", seq: 3).headers).not_to have_key(hdr::BATCH_COMMIT)
  end

  it "waits for acks on the first message and every ack_every messages" do
    seen = nc.subscribe("batch.>")
    batch = js.new_batch_publisher(ack_every: 3)
    7.times { |i| batch.add("batch.x", i.to_s) }
    batch.commit("batch.x", "last")

    replies = 8.times.map { seen.next_msg(timeout: 1) }.map { |m| m.reply.to_s.empty? ? nil : m.header[hdr::BATCH_SEQUENCE] }
    expect(replies.compact).to eql(%w[1 3 6 8])

    seen.unsubscribe
    seen = nc.subscribe("batch.>")
    batch = js.new_batch_publisher(ack_first: false)
    batch.add("batch.x", "1")
    batch.commit("batch.x", "2")
    expect(2.times.map { seen.next_msg(timeout: 1).reply.to_s.empty? }).to eql([true, false])
  end

  it "sets the headers of the message options" do
    js.publish("batch.a", "before")
    js.publish("batch.x", "before")

    batch = js.new_batch_publisher
    batch.add("batch.a", "one", ttl: 60, stream: "BATCH", expected_last_seq: 2, msg_id: "m1")
    batch.add("batch.b", "two", expected_last_subject_seq: 0)
    ack = batch.commit("batch.c", "three", expected_last_subject_seq: 2, expected_last_subject: "batch.x")

    expect(ack).to have_attributes(seq: 5, count: 3)
    expect(js.get_msg("BATCH", seq: 3).headers).to include(
      hdr::MSG_TTL => "60", hdr::EXPECTED_STREAM => "BATCH",
      hdr::EXPECTED_LAST_SEQUENCE => "2", hdr::MSG_ID => "m1"
    )
    expect(js.get_msg("BATCH", seq: 4).headers).to include(hdr::EXPECTED_LAST_SUBJECT_SEQUENCE => "0")
    expect(js.get_msg("BATCH", seq: 5).headers).to include(
      hdr::EXPECTED_LAST_SUBJECT_SEQUENCE => "2",
      hdr::EXPECTED_LAST_SUBJECT_SEQUENCE_SUBJECT => "batch.x"
    )
  end

  it "refuses the batch when an expectation fails" do
    batch = js.new_batch_publisher
    batch.add("batch.a", "one")

    expect { batch.commit("batch.b", "two", expected_last_seq: 99) }.to raise_error(errors::BadRequest) do |e|
      expect(e.err_code).to eql(10071)
    end
    expect(batch.closed?).to be(true)
    expect(messages).to eql(0)
  end

  it "raises ArgumentError for invalid options, before sending" do
    batch = js.new_batch_publisher
    expect { batch.add("batch.a", ttl: 0) }.to raise_error(ArgumentError)
    expect { batch.add("batch.a", stream: "") }.to raise_error(ArgumentError)
    expect { batch.add("batch.a", expected_last_seq: -1) }.to raise_error(ArgumentError)
    expect { batch.add("batch.a", expected_last_subject: "batch.a") }.to raise_error(ArgumentError)
    expect { batch.add("batch.a", expected_last_subject_seq: 1, expected_last_subject: "") }.to raise_error(ArgumentError)
    expect { batch.add("batch.a", bogus: 1) }.to raise_error(ArgumentError)
    expect(batch.size).to eql(0)

    expect { js.new_batch_publisher(ack_every: -1) }.to raise_error(ArgumentError)
    expect { js.new_batch_publisher(ack_first: nil) }.to raise_error(ArgumentError)
    expect { js.new_batch_publisher(ack_timeout: 0) }.to raise_error(ArgumentError)
  end

  describe "server errors" do
    it "raises BatchPublishNotEnabled for a stream without allow_atomic" do
      js.add_stream(name: "PLAIN", subjects: ["plain"])

      expect { js.new_batch_publisher.add("plain", "x") }.to raise_error(errors::BatchPublishNotEnabled) do |e|
        expect(e).to be_a(errors::BadRequest)
        expect(e).to have_attributes(code: 400, err_code: 10174)
      end
      expect { js.publish_msg_batch([NATS::Msg.new(subject: "plain")]) }.to raise_error(errors::BatchPublishNotEnabled)
    end

    it "raises BatchPublishDuplicateMsgID for a repeated message id" do
      batch = js.new_batch_publisher
      batch.add("batch.a", "one", msg_id: "dup")

      expect { batch.commit("batch.a", "two", msg_id: "dup") }.to raise_error(errors::BatchPublishDuplicateMsgID) do |e|
        expect(e.err_code).to eql(10201)
      end
    end

    it "raises BatchPublishUnsupportedHeader for Nats-Expected-Last-Msg-Id" do
      batch = js.new_batch_publisher
      batch.add("batch.a", "one", header: {hdr::EXPECTED_LAST_MSG_ID => "x"})
      expect { batch.commit("batch.a", "two") }
        .to raise_error(errors::BatchPublishUnsupportedHeader) { |e| expect(e.err_code).to eql(10177) }
    end

    it "raises BatchPublishIncomplete for a batch with a gap" do
      nc.publish("batch.a", "one", header: {hdr::BATCH_ID => "gap", hdr::BATCH_SEQUENCE => "1"})
      expect do
        js.publish("batch.a", "three", header: {hdr::BATCH_ID => "gap", hdr::BATCH_SEQUENCE => "3", hdr::BATCH_COMMIT => "1"})
      end.to raise_error(errors::BatchPublishIncomplete) { |e| expect(e.err_code).to eql(10176) }
    end

    it "raises BatchPublishInvalidID for an id of more than 64 characters" do
      expect do
        js.publish("batch.a", "x", header: {hdr::BATCH_ID => "x" * 65, hdr::BATCH_SEQUENCE => "1", hdr::BATCH_COMMIT => "1"})
      end.to raise_error(errors::BatchPublishInvalidID) { |e| expect(e.err_code).to eql(10179) }
    end

    it "raises BatchPublishInvalidCommit for an unknown commit value" do
      expect do
        js.publish("batch.a", "x", header: {hdr::BATCH_ID => "c", hdr::BATCH_SEQUENCE => "1", hdr::BATCH_COMMIT => "yes"})
      end.to raise_error(errors::BatchPublishInvalidCommit) { |e| expect(e.err_code).to eql(10200) }
    end

    it "raises BatchPublishExceedsLimit for a batch of more than 1000 messages" do
      batch = js.new_batch_publisher(ack_first: false)
      1000.times { batch.add("batch.a", "x") }

      expect { batch.commit("batch.a", "x") }.to raise_error(errors::BatchPublishExceedsLimit) do |e|
        expect(e.err_code).to eql(10199)
      end
    end

    it "raises MirrorWithAtomicPublish for a mirror with allow_atomic" do
      expect do
        js.add_stream(name: "PLAIN", mirror: {name: "BATCH"}, allow_atomic: true)
      end.to raise_error(errors::MirrorWithAtomicPublish) { |e| expect(e.err_code).to eql(10198) }
    end

    context "with a server that allows one batch in flight per stream" do
      before(:all) do
        @limited_dir = Dir.mktmpdir("ruby-jetstream")
        conf = File.join(@limited_dir, "js.conf")
        File.write(conf, <<~CONF)
          jetstream {
            store_dir: "#{@limited_dir}"
            limits { batch { max_inflight_per_stream: 1 } }
          }
        CONF
        @limited = NatsServerControl.new("nats://127.0.0.1:4863", "/tmp/test-nats-limited.pid", "-c #{conf}")
        @limited.start_server(true)
      end

      after(:all) do
        @limited.kill_server
        FileUtils.remove_entry(@limited_dir)
      end

      it "raises AtomicPublishTooManyInflight, with status code 429" do
        lnc = NATS.connect(@limited.uri)
        ljs = lnc.jetstream
        ljs.add_stream(name: "BATCH", subjects: ["batch.>"], allow_atomic: true)

        first = ljs.new_batch_publisher
        first.add("batch.a", "one")

        expect { ljs.new_batch_publisher.add("batch.b", "two") }.to raise_error(errors::AtomicPublishTooManyInflight) do |e|
          expect(e).to be_a(errors::BadRequest)
          expect(e).to have_attributes(code: 429, err_code: 10210)
        end
        expect(first.commit("batch.a", "two").count).to eql(2)
      ensure
        lnc&.close
      end
    end

    it "maps the error codes of nats-server, keeping 10204 for consumer resets" do
      from_error = ->(err) { NATS::JetStream.const_get(:JS).from_error(err) }

      expect(from_error.call(code: 429, err_code: 10210, description: "atomic publish too many inflight"))
        .to be_a(errors::AtomicPublishTooManyInflight).and have_attributes(code: 429)
      expect(from_error.call(code: 400, err_code: 10175)).to be_a(errors::BatchPublishMissingSeq)
      expect(from_error.call(code: 400, err_code: 10204)).to be_a(errors::ConsumerInvalidReset)
      expect(from_error.call(code: 429, err_code: 1)).to be_an_instance_of(errors::APIError)
      expect(errors::BATCH_PUBLISH_ERRORS.keys).to include(10174, 10176, 10177, 10179, 10199, 10200, 10201, 10210)
    end
  end
end

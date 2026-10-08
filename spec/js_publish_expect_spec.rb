# frozen_string_literal: true

describe "JetStream publish options for ids and expectations" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-publish-expect")
    @s = NatsServerControl.new("nats://127.0.0.1:4738", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  before { nc.jsm.add_stream(name: "EXP", subjects: ["exp.>"]) }

  after { nc.close }

  def headers(seq)
    nc.jsm.get_msg("EXP", seq: seq).headers
  end

  # Each way to publish, so that every one is checked with the options.
  publishers = {
    "publish" => ->(js, subject, data, **opts) { js.publish(subject, data, **opts) },
    "publish_async" => ->(js, subject, data, **opts) { js.publish_async(subject, data, **opts).wait(5) },
    "publish_msg" => ->(js, subject, data, **opts) { js.publish_msg(NATS::Msg.new(subject: subject, data: data), **opts) },
    "publish_msg_async" => lambda do |js, subject, data, **opts|
      js.publish_msg_async(NATS::Msg.new(subject: subject, data: data), **opts).wait(5)
    end
  }.freeze

  publishers.each do |name, pub|
    describe name do
      it "deduplicates by msg_id, setting Nats-Msg-Id" do
        ack = pub.call(js, "exp.a", "one", msg_id: "id-1")
        expect(ack.seq).to eql(1)
        expect(ack.duplicate).to be_falsey
        expect(headers(1)["Nats-Msg-Id"]).to eql("id-1")

        ack = pub.call(js, "exp.a", "again", msg_id: "id-1")
        expect(ack.seq).to eql(1)
        expect(ack.duplicate).to eql(true)
        expect(nc.jsm.stream_info("EXP").state.messages).to eql(1)
      end

      it "checks expected_last_seq, setting Nats-Expected-Last-Sequence" do
        expect(pub.call(js, "exp.a", "one", expected_last_seq: 0).seq).to eql(1)
        expect(headers(1)["Nats-Expected-Last-Sequence"]).to eql("0")
        expect(pub.call(js, "exp.b", "two", expected_last_seq: 1).seq).to eql(2)

        expect do
          pub.call(js, "exp.a", "three", expected_last_seq: 1)
        end.to raise_error(NATS::JetStream::Error::WrongLastSequence) { |e| expect(e.err_code).to eql(10071) }
      end

      it "checks expected_last_subject_seq, setting Nats-Expected-Last-Subject-Sequence" do
        expect(pub.call(js, "exp.a", "one", expected_last_subject_seq: 0).seq).to eql(1)
        expect(pub.call(js, "exp.b", "two", expected_last_subject_seq: 0).seq).to eql(2)
        expect(pub.call(js, "exp.a", "three", expected_last_subject_seq: 1).seq).to eql(3)
        expect(headers(3)["Nats-Expected-Last-Subject-Sequence"]).to eql("1")

        expect do
          pub.call(js, "exp.b", "four", expected_last_subject_seq: 1)
        end.to raise_error(NATS::JetStream::Error::WrongLastSequence)
      end

      it "checks expected_last_subject_seq on expected_last_subject" do
        pub.call(js, "exp.a", "one")
        pub.call(js, "exp.b", "two")
        ack = pub.call(js, "exp.c", "three", expected_last_subject_seq: 2, expected_last_subject: "exp.b")
        expect(ack.seq).to eql(3)
        expect(headers(3)["Nats-Expected-Last-Subject-Sequence"]).to eql("2")
        expect(headers(3)["Nats-Expected-Last-Subject-Sequence-Subject"]).to eql("exp.b")
        expect(pub.call(js, "exp.d", "four", expected_last_subject_seq: 3, expected_last_subject: "exp.*").seq).to eql(4)

        expect do
          pub.call(js, "exp.c", "five", expected_last_subject_seq: 3, expected_last_subject: "exp.a")
        end.to raise_error(NATS::JetStream::Error::WrongLastSequence)
      end

      it "checks expected_last_msg_id, setting Nats-Expected-Last-Msg-Id" do
        pub.call(js, "exp.a", "one", msg_id: "first")
        ack = pub.call(js, "exp.a", "two", msg_id: "second", expected_last_msg_id: "first")
        expect(ack.seq).to eql(2)
        expect(headers(2)["Nats-Expected-Last-Msg-Id"]).to eql("first")

        expect do
          pub.call(js, "exp.a", "three", expected_last_msg_id: "first")
        end.to raise_error(NATS::JetStream::Error::BadRequest) { |e| expect(e.err_code).to eql(10070) }
      end

      it "combines the options with the header and the expected stream" do
        ack = pub.call(js, "exp.a", "one", msg_id: "m1", stream: "EXP", expected_last_seq: 0)
        expect(ack.seq).to eql(1)
        expect(headers(1)).to include("Nats-Msg-Id" => "m1", "Nats-Expected-Stream" => "EXP",
          "Nats-Expected-Last-Sequence" => "0")
      end

      it "refuses invalid options before sending" do
        [
          {msg_id: ""}, {msg_id: 1}, {expected_last_seq: -1}, {expected_last_seq: "1"},
          {expected_last_subject_seq: 1.5}, {expected_last_subject: "exp.a"},
          {expected_last_subject: "", expected_last_subject_seq: 1}, {expected_last_msg_id: ""}
        ].each do |opts|
          expect { pub.call(js, "exp.a", "x", **opts) }.to raise_error(ArgumentError)
        end
        expect(js.publish_async_pending).to eql(0)
        expect(nc.jsm.stream_info("EXP").state.messages).to eql(0)
      end
    end
  end

  it "does not change the header given" do
    header = {"Kind" => "new"}
    js.publish("exp.a", "one", header: header, msg_id: "m1")
    js.publish_async("exp.a", "two", header: header, msg_id: "m2").wait(5)
    expect(header).to eql({"Kind" => "new"})
    expect(headers(2)).to include("Kind" => "new", "Nats-Msg-Id" => "m2")
  end
end

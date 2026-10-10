# frozen_string_literal: true

describe "JetStream publish_msg" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-publish-msg")
    @s = NatsServerControl.new("nats://127.0.0.1:4737", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  before { nc.jsm.add_stream(name: "MSGS", subjects: ["msgs.>"]) }

  after { nc.close }

  describe "publish_msg" do
    it "publishes the subject, data and header of a message and returns the ack" do
      msg = NATS::Msg.new(subject: "msgs.a", data: "hello", header: {"Kind" => "new"})
      ack = js.publish_msg(msg)
      expect(ack).to be_a(NATS::JetStream::PubAck)
      expect(ack.stream).to eql("MSGS")
      expect(ack.seq).to eql(1)

      stored = nc.jsm.get_msg("MSGS", seq: 1)
      expect(stored.subject).to eql("msgs.a")
      expect(stored.data).to eql("hello")
      expect(stored.headers["Kind"]).to eql("new")
    end

    it "takes the options of publish without changing the message" do
      msg = NATS::Msg.new(subject: "msgs.a", data: "hi", header: {"Kind" => "new"})
      js.publish_msg(msg, stream: "MSGS", timeout: 2)
      expect(msg.header).to eql({"Kind" => "new"})
      expect(msg.reply).to be_nil
      expect(nc.jsm.get_msg("MSGS", seq: 1).headers["Nats-Expected-Stream"]).to eql("MSGS")

      expect do
        js.publish_msg(msg, stream: "OTHER")
      end.to raise_error(NATS::JetStream::Error::BadRequest)
    end

    it "publishes a message without data or header" do
      ack = js.publish_msg(NATS::Msg.new(subject: "msgs.empty"))
      expect(ack.seq).to eql(1)
      expect(nc.jsm.get_msg("MSGS", seq: 1).data.to_s).to eql("")
    end

    it "ignores the reply of the message, as the ack comes to an inbox of its own" do
      msg = NATS::Msg.new(subject: "msgs.a", reply: "some.reply", data: "hi")
      expect(js.publish_msg(msg).seq).to eql(1)
      expect(msg.reply).to eql("some.reply")
    end

    it "refuses what is not a NATS::Msg, and a header option" do
      expect { js.publish_msg("msgs.a") }.to raise_error(TypeError)
      expect do
        js.publish_msg(NATS::Msg.new(subject: "msgs.a"), header: {"a" => "b"})
      end.to raise_error(ArgumentError)
    end

    it "raises NoStreamResponse when no stream takes the subject" do
      expect do
        js.publish_msg(NATS::Msg.new(subject: "nostream.a", data: "hi"), retry_attempts: 0)
      end.to raise_error(NATS::JetStream::Error::NoStreamResponse)
    end
  end

  describe "publish_msg_async" do
    it "publishes messages without waiting and acks each" do
      futures = 10.times.map do |i|
        js.publish_msg_async(NATS::Msg.new(subject: "msgs.a", data: "msg-#{i}", header: {"N" => i.to_s}))
      end
      expect(futures).to all(be_a(NATS::JetStream::PubAckFuture))
      js.publish_async_complete(timeout: 5)

      expect(futures.map { |future| future.ack.seq }).to eql((1..10).to_a)
      expect(futures.last.msg.data).to eql("msg-9")
      expect(futures.last.msg.reply).not_to be_empty
      expect(nc.jsm.get_msg("MSGS", seq: 10).headers["N"]).to eql("9")
    end

    it "takes the options of publish_async without changing the message" do
      msg = NATS::Msg.new(subject: "msgs.a", data: "hi", header: {"Kind" => "new"})
      future = js.publish_msg_async(msg, stream: "MSGS", timeout: 5)
      expect(future.wait(5).seq).to eql(1)
      expect(msg.reply).to be_nil
      expect(msg.header).to eql({"Kind" => "new"})
      expect(future.msg).not_to equal(msg)
      expect(future.msg.header).to eql({"Kind" => "new", "Nats-Expected-Stream" => "MSGS"})

      future = js.publish_msg_async(msg, stream: "OTHER")
      expect { future.wait(5) }.to raise_error(NATS::JetStream::Error::BadRequest)
    end

    it "raises AsyncPublishReplySubjectSet for a message with a reply, sending nothing" do
      msg = NATS::Msg.new(subject: "msgs.a", reply: "some.reply", data: "hi")
      expect do
        js.publish_msg_async(msg)
      end.to raise_error(NATS::JetStream::Error::AsyncPublishReplySubjectSet, "nats: reply subject should be empty")
      expect(js.publish_async_pending).to eql(0)
      expect(nc.jsm.stream_info("MSGS").state.messages).to eql(0)

      expect(js.publish_msg_async(NATS::Msg.new(subject: "msgs.a", reply: "")).wait(5).seq).to eql(1)
    end

    it "refuses what is not a NATS::Msg, and a header option" do
      expect { js.publish_msg_async("msgs.a") }.to raise_error(TypeError)
      expect do
        js.publish_msg_async(NATS::Msg.new(subject: "msgs.a"), header: {"a" => "b"})
      end.to raise_error(ArgumentError)
      expect(js.publish_async_pending).to eql(0)
    end
  end
end

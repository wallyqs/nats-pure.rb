# frozen_string_literal: true

describe "JetStream stream operations" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-stream-ops")
    @s = NatsServerControl.new("nats://127.0.0.1:4731", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  def publish_numbered(subjects, count)
    count.times do |i|
      js.publish(subjects[i % subjects.size], "msg-#{i}")
    end
  end

  describe "purge_stream" do
    before do
      nc.jsm.add_stream(name: "PURGE", subjects: ["purge.>"])
    end

    it "purges every message" do
      publish_numbered(["purge.a", "purge.b"], 10)

      resp = nc.jsm.purge_stream("PURGE")
      expect(resp).to be_a NATS::JetStream::API::StreamPurgeResponse
      expect(resp.success).to eql(true)
      expect(resp.purged).to eql(10)
      expect(nc.jsm.stream_info("PURGE").state.messages).to eql(0)
    end

    it "purges only the messages of a subject" do
      publish_numbered(["purge.a", "purge.b"], 10)

      resp = nc.jsm.purge_stream("PURGE", subject: "purge.a")
      expect(resp.purged).to eql(5)
      state = nc.jsm.stream_info("PURGE").state
      expect(state.messages).to eql(5)
      expect(nc.jsm.get_last_msg("PURGE", "purge.b").data).to eql("msg-9")
      expect do
        nc.jsm.get_last_msg("PURGE", "purge.a")
      end.to raise_error(NATS::JetStream::Error::NotFound)
    end

    it "purges the messages below a sequence" do
      publish_numbered(["purge.a"], 10)

      resp = nc.jsm.purge_stream("PURGE", seq: 8)
      expect(resp.purged).to eql(7)
      state = nc.jsm.stream_info("PURGE").state
      expect(state.messages).to eql(3)
      expect(state.first_seq).to eql(8)
    end

    it "keeps the latest messages" do
      publish_numbered(["purge.a", "purge.b"], 10)

      resp = nc.jsm.purge_stream("PURGE", keep: 2)
      expect(resp.purged).to eql(8)
      expect(nc.jsm.stream_info("PURGE").state.messages).to eql(2)

      # With a subject, keep counts the messages of that subject.
      publish_numbered(["purge.a"], 4)
      resp = nc.jsm.purge_stream("PURGE", subject: "purge.a", keep: 1)
      expect(resp.purged).to eql(4)
      expect(nc.jsm.stream_info("PURGE").state.messages).to eql(2)
    end

    it "refuses sequence and keep together" do
      expect do
        nc.jsm.purge_stream("PURGE", seq: 2, keep: 1)
      end.to raise_error(ArgumentError, /keep.*sequence/)
    end

    it "raises when the stream does not exist" do
      expect do
        nc.jsm.purge_stream("MISSING")
      end.to raise_error(NATS::JetStream::Error::StreamNotFound)

      expect do
        nc.jsm.purge_stream("")
      end.to raise_error(NATS::JetStream::Error::InvalidStreamName)
    end
  end

  describe "delete_msg" do
    before do
      nc.jsm.add_stream(name: "DEL", subjects: ["del.>"])
      publish_numbered(["del.a"], 3)
    end

    [:delete_msg, :secure_delete_msg].each do |method|
      it "#{method} deletes a message" do
        expect(nc.jsm.public_send(method, "DEL", 2)).to eql(true)

        state = nc.jsm.stream_info("DEL").state
        expect(state.messages).to eql(2)
        expect(nc.jsm.get_msg("DEL", seq: 1).data).to eql("msg-0")
        expect(nc.jsm.get_msg("DEL", seq: 3).data).to eql("msg-2")
        expect do
          nc.jsm.get_msg("DEL", seq: 2)
        end.to raise_error(NATS::JetStream::Error::NotFound)
      end

      it "#{method} raises for a message that is not stored" do
        nc.jsm.public_send(method, "DEL", 2)
        expect do
          nc.jsm.public_send(method, "DEL", 2)
        end.to raise_error(NATS::JetStream::Error::BadRequest)

        expect do
          nc.jsm.public_send(method, "MISSING", 1)
        end.to raise_error(NATS::JetStream::Error::StreamNotFound)
      end
    end
  end
end

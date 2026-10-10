# frozen_string_literal: true

describe "JetStream typed errors" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-errors")
    @s = NatsServerControl.new("nats://127.0.0.1:4733", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  # The error that the block raises, which has to be one.
  def error_of
    yield
  rescue => e
    e
  else
    raise "nothing raised"
  end

  describe "of the JetStream API" do
    before do
      js.add_stream(name: "S", subjects: ["s.>"], max_consumers: 1)
    end

    it "raises StreamNameAlreadyInUse for a stream name with another config" do
      err = error_of { js.add_stream(name: "S", subjects: ["other"]) }
      expect(err).to be_a(NATS::JetStream::Error::StreamNameAlreadyInUse)
      expect(err).to be_a(NATS::JetStream::Error::BadRequest)
      expect(err.err_code).to eql(10058)
    end

    it "raises MaximumConsumersLimit for a consumer too many" do
      js.add_consumer("S", durable_name: "one")
      err = error_of { js.add_consumer("S", durable_name: "two") }
      expect(err).to be_a(NATS::JetStream::Error::MaximumConsumersLimit)
      expect(err).to be_a(NATS::JetStream::Error::BadRequest)
      expect(err.err_code).to eql(10026)
    end

    it "raises the errors of invalid filter subjects" do
      {
        {filter_subject: "s.a", filter_subjects: ["s.b"]} => [NATS::JetStream::Error::DuplicateFilterSubjects, 10136],
        {filter_subjects: ["s.*", "s.a"]} => [NATS::JetStream::Error::OverlappingFilterSubjects, 10138],
        {filter_subjects: ["s.a", ""]} => [NATS::JetStream::Error::EmptyFilter, 10139]
      }.each do |config, (klass, err_code)|
        err = error_of { js.add_consumer("S", config) }
        expect(err).to be_a(klass)
        expect(err).to be_a(NATS::JetStream::Error::BadRequest)
        expect(err.err_code).to eql(err_code)
      end
    end

    it "raises ConsumerCreate when the server cannot create the consumer" do
      js.add_consumer("S", durable_name: "push", deliver_subject: "deliver")
      err = error_of { js.add_consumer("S", durable_name: "push") }
      expect(err).to be_a(NATS::JetStream::Error::ConsumerCreate)
      expect(err).to be_a(NATS::JetStream::Error::ServerError)
      expect(err.err_code).to eql(10012)
    end

    it "raises MsgNotFound for a message the stream does not have" do
      js.publish("s.a", "1")
      err = error_of { js.get_msg("S", seq: 99) }
      expect(err).to be_a(NATS::JetStream::Error::MsgNotFound)
      expect(err).to be_a(NATS::JetStream::Error::NotFound)
      expect(err.err_code).to eql(10037)
    end

    it "raises MsgNotFound for a message that a direct get does not find" do
      js.update_stream(js.stream_info("S").config.to_h.merge(allow_direct: true))
      err = error_of { js.get_msg("S", seq: 99, direct: true) }
      expect(err).to be_a(NATS::JetStream::Error::MsgNotFound)
      expect(err).to be_a(NATS::JetStream::Error::NotFound)
    end

    it "raises WrongLastSequence for a publish that expects another last sequence" do
      js.publish("s.a", "1")
      err = error_of { js.publish("s.a", "2", header: {"Nats-Expected-Last-Sequence" => "5"}) }
      expect(err).to be_a(NATS::JetStream::Error::WrongLastSequence)
      expect(err).to be_a(NATS::JetStream::Error::BadRequest)
      expect(err.err_code).to eql(10071)
    end

    it "raises the errors of message schedules" do
      err = error_of { js.publish("s.sched", "1", schedule: {every: 60, target: "s.target"}) }
      expect(err).to be_a(NATS::JetStream::Error::MessageSchedulesDisabled)
      expect(err).to be_a(NATS::JetStream::Error::BadRequest)
      expect(err.err_code).to eql(10188)

      js.add_stream(name: "SCHED", subjects: ["sched.>"], allow_msg_schedules: true)
      err = error_of { js.publish("sched.a", "1", schedule: {every: 60, target: "elsewhere"}) }
      expect(err).to be_a(NATS::JetStream::Error::ScheduleTargetInvalid)
      expect(err).to be_a(NATS::JetStream::Error::BadRequest)
      expect(err.err_code).to eql(10190)
    end

    it "keeps raising the generic error for an err_code it does not know" do
      err = error_of { js.add_stream(name: "OTHER", subjects: ["s.a"]) }
      expect(err.class).to eql(NATS::JetStream::Error::BadRequest)
      expect(err.err_code).to eql(10065)
    end
  end

  describe "of pulls" do
    before do
      js.add_stream(name: "S", subjects: ["s.>"])
    end

    it "raises ConsumerDeleted when the consumer of a fetch is deleted" do
      js.add_consumer("S", durable_name: "pull")
      psub = js.pull_subscribe("s.a", "pull", stream: "S")
      deleter = Thread.new do
        sleep 0.5
        js.delete_consumer("S", "pull")
      end
      err = error_of { psub.fetch(1, timeout: 5) }
      deleter.join
      expect(err).to be_a(NATS::JetStream::Error::ConsumerDeleted)
      expect(err).to be_a(NATS::JetStream::API::Error)
      expect(err.code).to eql("409")
    end
  end

  describe "for statuses" do
    let(:js_module) { NATS::JetStream.const_get(:JS) }

    def status_msg(code, desc)
      NATS::Msg.new(subject: "inbox", header: {"Status" => code, "Description" => desc})
    end

    it "maps the 409 statuses that end pulls as nats.go does" do
      {
        "Consumer Deleted" => NATS::JetStream::Error::ConsumerDeleted,
        "Leadership Change" => NATS::JetStream::Error::ConsumerLeadershipChanged,
        "Server Shutdown" => NATS::JetStream::Error::ServerShutdown
      }.each do |desc, klass|
        err = js_module.from_msg(status_msg("409", desc))
        expect(err).to be_a(klass)
        expect(err).to be_a(NATS::JetStream::API::Error)
        expect(err.code).to eql("409")
        expect(err.description).to eql(desc)
      end

      err = js_module.from_msg(status_msg("409", "Exceeded MaxWaiting"))
      expect(err.class).to eql(NATS::JetStream::API::Error)
    end

    it "maps err_codes only with the status code the server sends them with" do
      err = js_module.from_error(code: 400, err_code: 10013, description: "consumer name already in use")
      expect(err).to be_a(NATS::JetStream::Error::ConsumerNameAlreadyInUse)
      expect(err).to be_a(NATS::JetStream::Error::BadRequest)

      err = js_module.from_error(code: 503, err_code: 10076, description: "JetStream not enabled")
      expect(err).to be_a(NATS::JetStream::Error::JetStreamNotEnabled)
      expect(err).to be_a(NATS::JetStream::Error::ServiceUnavailable)

      err = js_module.from_error(code: 500, err_code: 10013, description: "other")
      expect(err.class).to eql(NATS::JetStream::Error::ServerError)

      err = js_module.from_error(code: 409, err_code: 10071, description: "other")
      expect(err.class).to eql(NATS::JetStream::API::Error)
    end
  end

  describe "of the client" do
    before do
      js.add_stream(name: "S", subjects: ["s.>"])
    end

    it "raises NotPullConsumer when a pull subscription binds to a push consumer" do
      js.add_consumer("S", durable_name: "push", deliver_subject: "deliver")
      expect do
        js.pull_subscribe("s.a", "push", stream: "S")
      end.to raise_error(NATS::JetStream::Error::NotPullConsumer)
    end

    it "raises NotPushConsumer when a push subscription binds to a pull consumer" do
      js.add_consumer("S", durable_name: "pull")
      expect do
        js.subscribe("s.a", stream: "S", durable: "pull")
      end.to raise_error(NATS::JetStream::Error::NotPushConsumer)
    end

    it "raises MsgNotBound and MsgNoReply for messages that cannot be acked" do
      msg = NATS::Msg.new(subject: "s.a", reply: "reply")
      [:ack, :ack_sync, :nak, :term, :in_progress].each do |method|
        expect { msg.public_send(method) }.to raise_error(NATS::JetStream::Error::MsgNotBound)
      end

      sub = nc.subscribe("plain")
      nc.publish("plain", "hi")
      msg = sub.next_msg
      [:ack, :ack_sync, :nak, :term, :in_progress].each do |method|
        expect { msg.public_send(method) }.to raise_error(NATS::JetStream::Error::MsgNoReply)
      end
    end

    it "raises InvalidJetStreamResponse for an API response that is not a JSON object" do
      fake = nc.jetstream(prefix: "FAKE.API")
      nc.subscribe("FAKE.API.STREAM.INFO.*") { |msg| msg.respond("not json") }
      nc.subscribe("FAKE.API.STREAM.NAMES") { |msg| msg.respond("[]") }
      nc.flush

      expect { fake.stream_info("S") }.to raise_error(NATS::JetStream::Error::InvalidJetStreamResponse)
      expect { fake.stream_names }.to raise_error(NATS::JetStream::Error::InvalidJetStreamResponse)
    end

    it "raises InvalidJSAck for a publish response that is not an ack" do
      nc.subscribe("plain.text") { |msg| msg.respond("not json") }
      nc.subscribe("plain.json") { |msg| msg.respond("{}") }
      nc.flush

      expect { js.publish("plain.text", "hi") }.to raise_error(NATS::JetStream::Error::InvalidJSAck)
      expect { js.publish("plain.json", "hi") }.to raise_error(NATS::JetStream::Error::InvalidJSAck)
    end
  end

  describe "of an account without JetStream" do
    before do
      @s.kill_server
      @s = NatsServerControl.init_with_config_from_string(%(
        port = 4734
        jetstream { store_dir = "#{@tmpdir}" }
        accounts {
          JS { jetstream = enabled, users = [{user = "js", password = "js"}] }
          NOJS { users = [{user = "nojs", password = "nojs"}] }
        }
      ), {"pid_file" => "/tmp/test-nats.pid", "host" => "127.0.0.1", "port" => 4734})
      @s.start_server(true)
    end

    let(:nc) { NATS.connect("nats://nojs:nojs@127.0.0.1:4734") }

    it "raises JetStreamNotEnabledForAccount" do
      err = error_of { nc.jsm.account_info }
      expect(err).to be_a(NATS::JetStream::Error::JetStreamNotEnabledForAccount)
      expect(err).to be_a(NATS::JetStream::Error::ServiceUnavailable)
      expect(err.err_code).to eql(10039)
    end
  end
end

# frozen_string_literal: true

describe "JetStream checks that the server applied the settings" do
  describe "against a server that applies them" do
    before do
      @tmpdir = Dir.mktmpdir("ruby-js-applied-settings")
      @s = NatsServerControl.new("nats://127.0.0.1:4744", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
      @s.start_server(true)
    end

    after do
      @s.kill_server
      FileUtils.remove_entry(@tmpdir)
    end

    let(:nc) { NATS.connect(@s.uri) }
    let(:js) { nc.jetstream }

    after { nc.close }

    it "creates and updates streams with subject transforms and sources" do
      resp = js.add_stream(name: "T", subjects: ["t.>"], subject_transform: {src: "t.>", dest: "x.>"})
      expect(resp.config.subject_transform).to eql(src: "t.>", dest: "x.>")
      js.update_stream(name: "T", subjects: ["t.>"], subject_transform: {src: "t.>", dest: "y.>"})

      js.add_stream(name: "A", subjects: ["a.>"])
      js.add_stream(name: "B", subjects: ["b.>"])
      sources = [
        {name: "A", subject_transforms: [{src: "a.x.>", dest: "from.x.>"}, {src: "a.y.>", dest: "from.y.>"}]},
        {name: "B"}
      ]
      resp = js.add_stream(name: "S", sources: sources)
      expect(resp.config.sources.size).to eql(2)
      js.update_stream(name: "S", sources: sources.reverse)
      js.create_or_update_stream(name: "S", sources: sources.take(1))
      expect(js.stream_info("S").config.sources.size).to eql(1)
    end

    it "creates consumers with filter subjects" do
      js.add_stream(name: "F", subjects: ["f.>"])
      info = js.add_consumer("F", durable_name: "multi", filter_subjects: ["f.a", "f.b"])
      expect(info.config.filter_subjects).to eql(["f.a", "f.b"])
      info = js.create_consumer("F", name: "one", filter_subjects: ["f.a"])
      expect(info.config.filter_subjects).to eql(["f.a"])
      psub = js.pull_subscribe(["f.a", "f.b"], "psub", stream: "F")
      expect(psub.consumer_info.config.filter_subjects).to eql(["f.a", "f.b"])
    end
  end

  describe "against a server that drops them" do
    before do
      # A JetStream API without the settings, as of servers that do not know them.
      @s = NatsServerControl.new("nats://127.0.0.1:4745", "/tmp/test-nats.pid")
      @s.start_server(true)
    end

    after do
      @s.kill_server
    end

    let(:nc) { NATS.connect(@s.uri) }
    let(:js) { nc.jetstream }
    let(:api) { NATS.connect(@s.uri) }

    after do
      nc.close
      api.close
    end

    # serve responds to the API requests on a subject with the config of
    # the request, changed by the block.
    def serve(subject)
      api.subscribe(subject) do |msg|
        req = JSON.parse(msg.data, symbolize_names: true)
        config = req[:config] || req
        resp = {config: yield(config), created: Time.now.utc.iso8601(9), state: {messages: 0}}
        resp.merge!(stream_name: req[:stream_name], name: config[:name] || config[:durable_name], delivered: {}, ack_floor: {}) if req[:config]
        msg.respond(resp.to_json)
      end
      api.flush
    end

    it "raises when a stream has no subject transform" do
      serve("$JS.API.STREAM.*.T") { |config| config.except(:subject_transform) }

      expect do
        js.add_stream(name: "T", subjects: ["t.>"], subject_transform: {src: "t.>", dest: "x.>"})
      end.to raise_error(NATS::JetStream::Error::StreamSubjectTransformNotSupported, "nats: stream subject transformation not supported by nats-server")
      expect do
        js.update_stream(name: "T", subjects: ["t.>"], subject_transform: {src: "t.>", dest: "x.>"})
      end.to raise_error(NATS::JetStream::Error::StreamSubjectTransformNotSupported)
      # A stream without one is fine.
      expect(js.add_stream(name: "T", subjects: ["t.>"]).config.name).to eql("T")
    end

    it "raises when a stream has no sources" do
      serve("$JS.API.STREAM.*.S") { |config| config.except(:sources) }

      expect do
        js.add_stream(name: "S", sources: [{name: "A"}])
      end.to raise_error(NATS::JetStream::Error::StreamSourceNotSupported, "nats: stream sourcing is not supported by nats-server")
      expect do
        js.create_or_update_stream(name: "S", sources: [{name: "A"}])
      end.to raise_error(NATS::JetStream::Error::StreamSourceNotSupported)
    end

    it "raises when the sources of a stream have no subject transforms" do
      serve("$JS.API.STREAM.*.S") do |config|
        config.merge(sources: config[:sources].map { |source| source.except(:subject_transforms) }.reverse)
      end

      sources = [{name: "A", subject_transforms: [{src: "a.>", dest: "b.>"}]}, {name: "B"}]
      expect do
        js.add_stream(name: "S", sources: sources)
      end.to raise_error(NATS::JetStream::Error::StreamSourceSubjectTransformNotSupported) { |e|
        expect(e).to be_a(NATS::JetStream::Error::StreamSubjectTransformNotSupported)
      }
      expect do
        js.update_stream(name: "S", sources: sources)
      end.to raise_error(NATS::JetStream::Error::StreamSourceSubjectTransformNotSupported)

      # Sources without transforms, in any order, are fine.
      expect(js.add_stream(name: "S", sources: [{name: "A"}, {name: "B"}]).config.sources.size).to eql(2)
    end

    it "raises when a consumer has no filter subjects" do
      serve("$JS.API.CONSUMER.CREATE.F.>") { |config| config.except(:filter_subjects) }
      serve("$JS.API.CONSUMER.DURABLE.CREATE.F.>") { |config| config.except(:filter_subjects) }

      expect do
        js.add_consumer("F", durable_name: "multi", filter_subjects: ["f.a", "f.b"])
      end.to raise_error(NATS::JetStream::Error::ConsumerMultipleFilterSubjectsNotSupported, "nats: multiple consumer filter subjects not supported by nats-server")
      expect do
        js.create_consumer("F", name: "multi", filter_subjects: ["f.a"])
      end.to raise_error(NATS::JetStream::Error::ConsumerMultipleFilterSubjectsNotSupported)
      # A consumer with one filter subject is fine.
      expect(js.add_consumer("F", durable_name: "one", filter_subject: "f.a").config.filter_subject).to eql("f.a")
    end
  end
end

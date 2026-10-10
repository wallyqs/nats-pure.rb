# frozen_string_literal: true

describe "JetStream stream and consumer listing" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-list")
    @s = NatsServerControl.new("nats://127.0.0.1:4732", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }

  after { nc.close }

  describe "streams" do
    it "lists nothing without streams" do
      expect(nc.jsm.stream_names).to eql([])
      expect(nc.jsm.streams).to eql([])
    end

    it "lists the streams" do
      nc.jsm.add_stream(name: "B", subjects: ["b.>"])
      nc.jsm.add_stream(name: "A", subjects: ["a.*"])

      expect(nc.jsm.stream_names).to eql(["A", "B"])
      infos = nc.jsm.streams
      expect(infos).to all(be_a(NATS::JetStream::API::StreamInfo))
      expect(infos.map { |info| info.config.name }).to eql(["A", "B"])
      expect(infos.map { |info| info.config.subjects }).to eql([["a.*"], ["b.>"]])
    end

    it "lists only the streams that take a subject" do
      nc.jsm.add_stream(name: "A", subjects: ["a.*"])
      nc.jsm.add_stream(name: "B", subjects: ["b.x"])
      nc.jsm.add_stream(name: "C", subjects: ["b.y"])

      expect(nc.jsm.stream_names(subject: "a.x")).to eql(["A"])
      expect(nc.jsm.stream_names(subject: "b.*")).to eql(["B", "C"])
      expect(nc.jsm.stream_names(subject: "b.y")).to eql(["C"])
      expect(nc.jsm.stream_names(subject: "z")).to eql([])
      expect(nc.jsm.streams(subject: "b.>").map { |info| info.config.name }).to eql(["B", "C"])
    end

    it "requests every page of streams" do
      # The server lists at most 256 streams per page.
      count = 260
      count.times do |i|
        nc.jsm.add_stream(name: format("S%03d", i), subjects: ["s.#{i}"], storage: "memory")
      end

      names = (0...count).map { |i| format("S%03d", i) }
      expect(nc.jsm.stream_names).to eql(names)
      expect(nc.jsm.streams.map { |info| info.config.name }).to eql(names)
    end
  end

  describe "consumers" do
    before do
      nc.jsm.add_stream(name: "CONS", subjects: ["cons.>"], storage: "memory")
    end

    it "lists nothing without consumers" do
      expect(nc.jsm.consumer_names("CONS")).to eql([])
      expect(nc.jsm.consumers("CONS")).to eql([])
    end

    it "lists the consumers of a stream" do
      nc.jsm.add_consumer("CONS", durable_name: "b")
      nc.jsm.add_consumer("CONS", durable_name: "a", filter_subject: "cons.a")

      expect(nc.jsm.consumer_names("CONS")).to eql(["a", "b"])
      infos = nc.jsm.consumers("CONS")
      expect(infos).to all(be_a(NATS::JetStream::API::ConsumerInfo))
      expect(infos.map(&:name)).to eql(["a", "b"])
      expect(infos.first.config.filter_subject).to eql("cons.a")
      expect(infos.map(&:stream_name)).to eql(["CONS", "CONS"])
    end

    it "requests every page of consumers" do
      # The server lists at most 256 consumers per page.
      count = 260
      count.times do |i|
        nc.jsm.add_consumer("CONS", durable_name: format("c%03d", i))
      end

      names = (0...count).map { |i| format("c%03d", i) }
      expect(nc.jsm.consumer_names("CONS")).to eql(names)
      expect(nc.jsm.consumers("CONS").map(&:name)).to eql(names)
    end

    it "raises for a stream that does not exist" do
      expect do
        nc.jsm.consumer_names("MISSING")
      end.to raise_error(NATS::JetStream::Error::StreamNotFound)
      expect do
        nc.jsm.consumers("MISSING")
      end.to raise_error(NATS::JetStream::Error::StreamNotFound)
    end

    it "raises for an invalid stream name" do
      expect do
        nc.jsm.consumer_names("")
      end.to raise_error(NATS::JetStream::Error::InvalidStreamName)
      expect do
        nc.jsm.consumers(nil)
      end.to raise_error(NATS::JetStream::Error::InvalidStreamName)
    end
  end

  describe "paging" do
    # A responder that serves the names in pages of two, as the server
    # serves its pages, recording the requests.
    let(:names) { ["A", "B", "C", "D", "E"] }
    let(:total) { names.size }
    let(:requests) { [] }
    let(:js) { nc.jetstream(prefix: "FAKE.API") }

    before do
      nc.subscribe("FAKE.API.>") do |msg|
        req = JSON.parse(msg.data, symbolize_names: true)
        requests << [msg.subject, req]
        offset = req[:offset]
        key = msg.subject.include?("CONSUMER") ? :consumers : :streams
        msg.respond({total: total, offset: offset, limit: 2}.merge(key => names[offset, 2]).to_json)
      end
      nc.flush
    end

    it "requests the pages from offset 0 until it has the total" do
      expect(js.stream_names(subject: "x.>")).to eql(names)
      expect(requests).to eql([
        ["FAKE.API.STREAM.NAMES", {offset: 0, subject: "x.>"}],
        ["FAKE.API.STREAM.NAMES", {offset: 2, subject: "x.>"}],
        ["FAKE.API.STREAM.NAMES", {offset: 4, subject: "x.>"}]
      ])

      requests.clear
      expect(js.consumer_names("S")).to eql(names)
      expect(requests.map(&:last)).to eql([{offset: 0}, {offset: 2}, {offset: 4}])
      expect(requests.map(&:first).uniq).to eql(["FAKE.API.CONSUMER.NAMES.S"])
    end

    context "with a page that adds nothing" do
      let(:total) { 10 }

      it "stops there" do
        expect(js.stream_names).to eql(names)
        expect(requests.map(&:last)).to eql([{offset: 0}, {offset: 2}, {offset: 4}, {offset: 5}])
      end
    end
  end
end

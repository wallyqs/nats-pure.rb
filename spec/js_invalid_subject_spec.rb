# frozen_string_literal: true

describe "JetStream invalid subjects" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-invalid-subject")
    @s = NatsServerControl.new("nats://127.0.0.1:4737", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:requests) { nc.subscribe("$JS.API.>") }

  before do
    js.add_stream(name: "S", subjects: ["foo.>"])
    requests
    nc.flush
  end

  after { nc.close }

  # The invalid subjects of validateSubject of nats.go, and whitespace.
  let(:invalid) { ["", ".foo", "foo.", "foo bar", "foo.>.bar", ">.foo", "foo\tbar", "foo\r\nbar"] }

  def requests_sent
    nc.flush
    Array.new(requests.pending_queue.size) { requests.next_msg.subject }
  end

  it "refuses to look a stream up by an invalid subject" do
    invalid.each do |subject|
      expect { js.find_stream_name_by_subject(subject) }.to raise_error(NATS::JetStream::Error::InvalidSubject)
    end
    expect(requests_sent).to be_empty

    expect { js.find_stream_name_by_subject(nil) }.to raise_error(NATS::JetStream::Error::InvalidSubject, "nats: invalid subject name: subject cannot be empty")
    expect { js.find_stream_name_by_subject("foo.") }.to raise_error(NATS::JetStream::Error::InvalidSubject, "nats: invalid subject name: foo.")
    # Rescuing the NotFound raised before still works.
    expect { js.find_stream_name_by_subject("foo bar") }.to raise_error(NATS::JetStream::Error::NotFound)
  end

  it "looks streams up by valid subjects" do
    %w[foo.a foo.* foo.> > foo.*.bar].each do |subject|
      expect(js.find_stream_name_by_subject(subject)).to eql("S")
    end
    expect { js.find_stream_name_by_subject("bar") }.to raise_error(NATS::JetStream::Error::NotFound)
  end

  it "refuses to create a consumer with an invalid filter subject" do
    invalid.reject(&:empty?).each do |subject|
      expect { js.add_consumer("S", name: "c1", filter_subject: subject) }.to raise_error(NATS::JetStream::Error::InvalidSubject)
      expect { js.add_consumer("S", durable_name: "c1", filter_subject: subject) }.to raise_error(NATS::JetStream::Error::InvalidSubject)
      expect { js.create_consumer("S", name: "c1", filter_subjects: ["foo.a", subject]) }.to raise_error(NATS::JetStream::Error::InvalidSubject)
    end
    expect { js.update_consumer("S", name: "c1", filter_subjects: ["foo.a", "foo.>.b"]) }.to raise_error(NATS::JetStream::Error::InvalidSubject)
    expect(requests_sent).to be_empty
  end

  it "creates consumers with valid filter subjects" do
    expect(js.add_consumer("S", name: "c1", filter_subject: "foo.*").config.filter_subject).to eql("foo.*")
    expect(js.add_consumer("S", name: "c2", filter_subjects: ["foo.a", "foo.b.>"]).config.filter_subjects).to eql(["foo.a", "foo.b.>"])
    expect(js.add_consumer("S", name: "c3", filter_subject: ">").config.filter_subject).to eql(">")
  end

  it "refuses to subscribe to an invalid subject without a stream" do
    expect { js.pull_subscribe("foo bar", "c1") }.to raise_error(NATS::JetStream::Error::InvalidSubject)
    expect { js.pull_subscribe(["foo.a", "foo."], "c1") }.to raise_error(NATS::JetStream::Error::InvalidSubject)
    expect { js.subscribe("foo.") }.to raise_error(NATS::JetStream::Error::InvalidSubject)
    # Only the lookup of the valid subject went out.
    expect(requests_sent).to eql(["$JS.API.STREAM.NAMES"])
  end
end

# frozen_string_literal: true

describe "JetStream create_or_update_stream" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-create-or-update-stream")
    @s = NatsServerControl.new("nats://127.0.0.1:4741", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }

  after { nc.close }

  it "creates a stream that does not exist" do
    resp = nc.jsm.create_or_update_stream(name: "ORDERS", subjects: ["orders.>"])
    expect(resp).to be_a(NATS::JetStream::API::StreamCreateResponse)
    expect(resp.config.name).to eql("ORDERS")
    expect(resp.config.subjects).to eql(["orders.>"])

    expect(nc.jsm.stream_info("ORDERS").config.subjects).to eql(["orders.>"])
  end

  it "updates a stream that exists" do
    nc.jsm.add_stream(name: "ORDERS", subjects: ["orders.>"])
    nc.jetstream.publish("orders.1", "one")

    config = NATS::JetStream::API::StreamConfig.new(name: "ORDERS", subjects: ["orders.>", "invoices.>"], max_msgs: 10)
    resp = nc.jsm.create_or_update_stream(config)
    expect(resp.config.subjects).to eql(["orders.>", "invoices.>"])
    expect(resp.config.max_msgs).to eql(10)

    # The stream was updated, not created again: it keeps its messages.
    info = nc.jsm.stream_info("ORDERS")
    expect(info.config.max_msgs).to eql(10)
    expect(info.state.messages).to eql(1)
  end

  it "raises the errors of an update that the server refuses" do
    nc.jsm.add_stream(name: "ORDERS", subjects: ["orders.>"], storage: "file")

    # The storage of a stream cannot change.
    expect do
      nc.jsm.create_or_update_stream(name: "ORDERS", subjects: ["orders.>"], storage: "memory")
    end.to raise_error(NATS::JetStream::Error::ServerError, /can not change storage type/)
    expect(nc.jsm.stream_info("ORDERS").config.storage).to eql("file")
  end

  it "raises the errors of a create that the server refuses" do
    nc.jsm.add_stream(name: "ORDERS", subjects: ["orders.>"])

    # The subjects overlap with those of another stream.
    expect do
      nc.jsm.create_or_update_stream(name: "OTHER", subjects: ["orders.eu"])
    end.to raise_error(NATS::JetStream::Error::BadRequest)
    expect(nc.jsm.stream_names).to eql(["ORDERS"])
  end

  it "validates the stream name" do
    expect { nc.jsm.create_or_update_stream(subjects: ["foo"]) }.to raise_error(ArgumentError)
    expect { nc.jsm.create_or_update_stream(name: "a.b") }.to raise_error(ArgumentError)
  end
end

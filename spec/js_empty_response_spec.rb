# frozen_string_literal: true

describe "JetStream empty consumer responses" do
  before do
    @s = NatsServerControl.new("nats://127.0.0.1:4735", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after do
    @s.kill_server
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:jsm) { nc.jsm }

  after { nc.close }

  # Answers the consumer API in place of JetStream, with a response that
  # is not an error but has no consumer info, as a server could.
  def answer(subject, response)
    nc.subscribe(subject) { |msg| msg.respond(response.to_json) }
    nc.flush
  end

  it "raises ConsumerCreationResponseEmpty when a creation has no consumer info" do
    answer("$JS.API.CONSUMER.>", {type: "io.nats.jetstream.api.v1.consumer_create_response"})

    expect { jsm.add_consumer("S", durable_name: "c1") }.to raise_error(NATS::JetStream::Error::ConsumerCreationResponseEmpty, "nats: consumer creation response is empty")
    expect { jsm.create_consumer("S", name: "c1") }.to raise_error(NATS::JetStream::Error::ConsumerCreationResponseEmpty)
    expect { jsm.update_consumer("S", name: "c1") }.to raise_error(NATS::JetStream::Error::ConsumerCreationResponseEmpty)
    expect { jsm.add_consumer("S", {}) }.to raise_error(NATS::JetStream::Error::ConsumerCreationResponseEmpty)
  end

  it "raises ConsumerResetResponseEmpty when a reset has no consumer info" do
    answer("$JS.API.CONSUMER.RESET.S.c1", {type: "io.nats.jetstream.api.v1.consumer_reset_response", reset_seq: 1})

    expect { jsm.reset_consumer("S", "c1") }.to raise_error(NATS::JetStream::Error::ConsumerResetResponseEmpty, "nats: consumer reset response is empty")
  end

  it "still raises the error of an error response" do
    answer("$JS.API.CONSUMER.>", {type: "io.nats.jetstream.api.v1.consumer_create_response", error: {code: 404, err_code: 10059, description: "stream not found"}})

    expect { jsm.add_consumer("S", durable_name: "c1") }.to raise_error(NATS::JetStream::Error::StreamNotFound)
    expect { jsm.reset_consumer("S", "c1") }.to raise_error(NATS::JetStream::Error::StreamNotFound)
  end
end

describe "JetStream consumer responses" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-empty-response")
    @s = NatsServerControl.new("nats://127.0.0.1:4736", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  it "takes the consumer info of a real server" do
    nc = NATS.connect(@s.uri)
    nc.jsm.add_stream(name: "S", subjects: ["s.>"])
    expect(nc.jsm.add_consumer("S", durable_name: "c1").name).to eql("c1")
    expect(nc.jsm.create_consumer("S", name: "c2").name).to eql("c2")
    nc.close
  end
end

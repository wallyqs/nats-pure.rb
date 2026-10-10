# frozen_string_literal: true

describe "JetStream ConsumerExistingActive" do
  before do
    # nats-server 2.15 updates or returns a durable consumer created again
    # before it gets to err_code 10105, so the API is answered here by a
    # responder that sends the error the server defines.
    @s = NatsServerControl.new("nats://127.0.0.1:4879", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after { @s.kill_server }

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  let(:existing_active) do
    {code: 400, err_code: 10105, description: "consumer already exists and is still active"}
  end

  it "raises ConsumerExistingActive, a BadRequest, for err_code 10105" do
    nc.subscribe("$JS.API.CONSUMER.*.S.>") do |msg|
      msg.respond({type: "io.nats.jetstream.api.v1.consumer_create_response", error: existing_active}.to_json)
    end
    nc.flush

    expect do
      js.add_consumer("S", durable_name: "d", deliver_subject: "dlv")
    end.to raise_error(NATS::JetStream::Error::ConsumerExistingActive) { |err|
      expect(err).to be_a(NATS::JetStream::Error::BadRequest)
      expect(err).not_to be_a(NATS::JetStream::Error::ConsumerAlreadyExists)
      expect(err.err_code).to eql(10105)
      expect(err.code).to eql(400)
      expect(err.description).to eql("consumer already exists and is still active")
    }
  end

  it "maps err_code 10105 only with the status code 400" do
    js_module = NATS::JetStream.const_get(:JS)
    expect(js_module.from_error(existing_active)).to be_a(NATS::JetStream::Error::ConsumerExistingActive)
    expect(js_module.from_error(existing_active.merge(code: 500)).class).to eql(NATS::JetStream::Error::ServerError)
  end
end

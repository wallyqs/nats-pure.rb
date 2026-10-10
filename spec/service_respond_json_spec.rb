# frozen_string_literal: true

RSpec.describe "Service request respond_json" do
  before(:all) do
    @server = NatsServerControl.new("nats://127.0.0.1:4523", "/tmp/test-nats.pid", "")
    @server.start_server(true)
  end

  after(:all) do
    @server.kill_server
  end

  let(:client) { NATS.connect("nats://127.0.0.1:4523") }
  let(:service) { client.services.add(name: "json", version: "1.0.0") }

  after { client.close }

  it "responds with the object as JSON" do
    service.endpoints.add("hash") { |req| req.respond_json({sum: 3, items: [1, 2], name: "x"}) }
    service.endpoints.add("array") { |req| req.respond_json([1, "two", nil]) }
    service.endpoints.add("string") { |req| req.respond_json("hi") }

    expect(JSON.parse(client.request("hash", "").data)).to eq("sum" => 3, "items" => [1, 2], "name" => "x")
    expect(client.request("array", "").data).to eq('[1,"two",null]')
    expect(client.request("string", "").data).to eq('"hi"')
  end

  it "raises MarshalResponseError and sends nothing when obj cannot be generated" do
    errors = Queue.new
    service.endpoints.add("nan") do |req|
      req.respond_json(Float::NAN)
    rescue => e
      errors << e
    end

    expect { client.request("nan", "", timeout: 0.3) }.to raise_error(NATS::Timeout)

    error = errors.pop
    expect(error).to be_a(NATS::Service::MarshalResponseError)
    expect(error).to be_a(NATS::Service::Error)
    expect(error.message).to start_with("marshaling response")
    expect(error.cause).to be_a(JSON::GeneratorError)
  end

  it "answers an unhandled marshal error with a 500" do
    endpoint = service.endpoints.add("bad") { |req| req.respond_json(Float::INFINITY) }

    resp = client.request("bad", "")

    expect(resp.header["Nats-Service-Error-Code"]).to eq("500")
    expect(resp.header["Nats-Service-Error"]).to start_with("marshaling response")
    expect(endpoint.stats.num_errors).to eq(1)
    expect(service.stopped?).to be(false)
  end
end

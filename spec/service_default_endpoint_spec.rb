# frozen_string_literal: true

RSpec.describe "Service default endpoint" do
  before(:all) do
    @server = NatsServerControl.new("nats://127.0.0.1:4541", "/tmp/test-nats.pid", "")
    @server.start_server(true)
  end

  after(:all) do
    @server.kill_server
  end

  let(:client) { NATS.connect("nats://127.0.0.1:4541") }

  after { client.close }

  it "adds the endpoint when the service is created" do
    service = client.services.add(
      name: "echo",
      version: "1.0.0",
      queue: "workers",
      endpoint: {
        subject: "echo.it",
        metadata: {"kind" => "echo"},
        handler: ->(req) { req.respond("echo: #{req.data}") }
      }
    )

    expect(service.endpoints.count).to eq(1)
    endpoint = service.endpoints.first
    expect(endpoint).to have_attributes(
      name: NATS::Service::DEFAULT_ENDPOINT, subject: "echo.it", queue: "workers", metadata: {"kind" => "echo"}
    )
    expect(NATS::Service::DEFAULT_ENDPOINT).to eq("default")

    expect(client.request("echo.it", "hi").data).to eq("echo: hi")
    wait_until { endpoint.stats.num_requests == 1 }

    info = JSON.parse(client.request("$SRV.INFO.echo", "").data)
    expect(info["endpoints"]).to eq([
      {"name" => "default", "subject" => "echo.it", "queue_group" => "workers", "metadata" => {"kind" => "echo"}}
    ])
  end

  it "takes the handler as the block of add" do
    service = client.services.add(name: "hi", version: "1.0.0", endpoint: {subject: "hi"}) do |req|
      req.respond("Hi!")
    end

    expect(client.request("hi", "").data).to eq("Hi!")
    expect(service.endpoints.map(&:name)).to eq(["default"])
  end

  it "registers the endpoint on its name without a subject, in the endpoint's own queue group" do
    service = client.services.add(
      name: "plain", version: "1.0.0", queue: "workers",
      endpoint: {queue: "own", handler: ->(req) { req.respond("ok") }}
    )

    expect(service.endpoints.first).to have_attributes(subject: "default", queue: "own")
    expect(client.request("default", "").data).to eq("ok")
  end

  it "adds more endpoints next to the default one" do
    service = client.services.add(name: "more", version: "1.0.0", endpoint: {subject: "more.a"}) { |req| req.respond("a") }
    service.endpoints.add("b", subject: "more.b") { |req| req.respond("b") }

    expect(service.endpoints.map(&:name)).to eq(%w[default b])
    expect(client.request("more.b", "").data).to eq("b")
  end

  it "does not create the service when the endpoint is invalid" do
    expect do
      client.services.add(name: "bad", version: "1.0.0", endpoint: {subject: "bad subject"}) { |req| req.respond("") }
    end.to raise_error(NATS::Service::InvalidSubjectError)

    expect do
      client.services.add(name: "bad", version: "1.0.0", endpoint: {subject: "nohandler"})
    end.to raise_error(ArgumentError, "endpoint handler is required")

    expect(client.services.to_a).to be_empty
    expect { client.request("$SRV.PING.bad", "", timeout: 0.2) }.to raise_error(NATS::IO::NoRespondersError)
  end

  it "has no endpoint without the option" do
    service = client.services.add(name: "none", version: "1.0.0")

    expect(service.endpoints.to_a).to be_empty
  end
end

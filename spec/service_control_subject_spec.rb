# frozen_string_literal: true

RSpec.describe "NATS::Service.control_subject" do
  before(:all) do
    @server = NatsServerControl.new("nats://127.0.0.1:4525", "/tmp/test-nats.pid", "")
    @server.start_server(true)
  end

  after(:all) do
    @server.kill_server
  end

  let(:client) { NATS.connect("nats://127.0.0.1:4525") }

  after { client.close }

  it "builds the subjects of nats.go micro" do
    expect(NATS::Service.control_subject(:ping)).to eq("$SRV.PING")
    expect(NATS::Service.control_subject(:info, "calc")).to eq("$SRV.INFO.calc")
    expect(NATS::Service.control_subject(:stats, "calc", "ID1")).to eq("$SRV.STATS.calc.ID1")
    expect(NATS::Service.control_subject("PING", "calc")).to eq("$SRV.PING.calc")
    expect(NATS::Service.control_subject("Info", "", "")).to eq("$SRV.INFO")
  end

  it "raises VerbNotSupportedError for other verbs" do
    expect { NATS::Service.control_subject(:schema) }
      .to raise_error(NATS::Service::VerbNotSupportedError, /unsupported verb/)
    expect { NATS::Service.control_subject(nil) }
      .to raise_error(NATS::Service::VerbNotSupportedError)
    expect { NATS::Service.control_subject(0) }
      .to raise_error(NATS::Service::VerbNotSupportedError)
  end

  it "raises ServiceNameRequiredError for an id without a name" do
    expect { NATS::Service.control_subject(:ping, nil, "ID1") }
      .to raise_error(NATS::Service::ServiceNameRequiredError, "service name is required to generate ID control subject")
    expect { NATS::Service.control_subject(:ping, "", "ID1") }
      .to raise_error(NATS::Service::ServiceNameRequiredError)
    expect(NATS::Service::ServiceNameRequiredError.ancestors).to include(NATS::Service::Error)
  end

  it "reaches a running service on every control subject" do
    service = client.services.add(name: "calc", version: "1.0.0")
    client.services.add(name: "other", version: "1.0.0")

    {ping: "ping_response", info: "info_response", stats: "stats_response"}.each do |verb, type|
      resp = client.request(NATS::Service.control_subject(verb, "calc", service.id), "")
      body = JSON.parse(resp.data)
      expect(body).to include("id" => service.id, "type" => "io.nats.micro.v1.#{type}")

      resp = client.request(NATS::Service.control_subject(verb, "calc"), "")
      expect(JSON.parse(resp.data)["name"]).to eq("calc")
    end

    names = []
    sub = client.subscribe(client.new_inbox) { |msg| names << JSON.parse(msg.data)["name"] }
    client.publish(NATS::Service.control_subject(:ping), "", sub.subject)
    client.flush
    sleep 0.2
    expect(names).to contain_exactly("calc", "other")
  end

  it "names the error headers" do
    expect(NATS::Service::ERROR_HEADER).to eq("Nats-Service-Error")
    expect(NATS::Service::ERROR_CODE_HEADER).to eq("Nats-Service-Error-Code")

    service = client.services.add(name: "calc", version: "1.0.0")
    service.endpoints.add("fail") { |req| req.respond_with_error({code: 400, description: "bad"}) }

    resp = client.request("fail", "")
    expect(resp.header[NATS::Service::ERROR_HEADER]).to eq("bad")
    expect(resp.header[NATS::Service::ERROR_CODE_HEADER]).to eq("400")
  end
end

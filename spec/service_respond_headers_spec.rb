# frozen_string_literal: true

RSpec.describe "Service response headers" do
  before(:all) do
    @server = NatsServerControl.new("nats://127.0.0.1:4524", "/tmp/test-nats.pid", "")
    @server.start_server(true)
  end

  after(:all) do
    @server.kill_server
  end

  let(:client) { NATS.connect("nats://127.0.0.1:4524") }
  let(:service) { client.services.add(name: "hdrs", version: "1.0.0") }

  after { client.close }

  def request(subject, header: {"X-Request" => "yes"})
    client.request_msg(NATS::Msg.new(subject: subject, data: "req", header: header), timeout: 1)
  end

  it "does not echo the request's headers or reply subject" do
    service.endpoints.add("plain") { |req| req.respond("ok") }

    resp = request("plain")

    expect(resp.data).to eq("ok")
    expect(resp.header).to be_nil
    expect(resp.reply.to_s).to eq("")
  end

  it "sends the given headers" do
    service.endpoints.add("with") { |req| req.respond("ok", headers: {"X-Response" => "1", "X-Other" => "2"}) }

    resp = request("with")

    expect(resp.data).to eq("ok")
    expect(resp.header).to eq("X-Response" => "1", "X-Other" => "2")
  end

  it "sends headers with respond_json" do
    service.endpoints.add("json") { |req| req.respond_json({a: 1}, headers: {"Content-Type" => "application/json"}) }

    resp = request("json", header: nil)

    expect(resp.data).to eq('{"a":1}')
    expect(resp.header).to eq("Content-Type" => "application/json")
  end

  it "adds headers to an error response, where they can override the error headers" do
    service.endpoints.add("err") do |req|
      req.respond_with_error({code: 404, description: "missing", data: "d"}, headers: {"X-Trace" => "t"})
    end
    service.endpoints.add("override") do |req|
      req.respond_with_error("boom", headers: {"Nats-Service-Error-Code" => "503"})
    end

    resp = request("err")
    expect(resp.data).to eq("d")
    expect(resp.header).to eq(
      "Nats-Service-Error" => "missing",
      "Nats-Service-Error-Code" => "404",
      "X-Trace" => "t"
    )

    resp = request("override")
    expect(resp.header).to eq("Nats-Service-Error" => "boom", "Nats-Service-Error-Code" => "503")
  end

  it "answers monitoring requests without the request's headers" do
    service

    resp = request("$SRV.PING.hdrs")

    expect(resp.header).to be_nil
    expect(JSON.parse(resp.data)).to include("name" => "hdrs", "type" => "io.nats.micro.v1.ping_response")
  end

  it "keeps the service running when a monitoring request has no reply subject" do
    service

    client.publish("$SRV.PING.hdrs", "")
    client.flush
    sleep 0.1

    expect(service.stopped?).to be(false)
    expect(client.request("$SRV.PING.hdrs", "").data).to include("hdrs")
  end
end

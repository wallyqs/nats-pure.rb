# frozen_string_literal: true

RSpec.describe "Service error handling" do
  before(:all) do
    @server = NatsServerControl.new("nats://127.0.0.1:4522", "/tmp/test-nats.pid", "")
    @server.start_server(true)
  end

  after(:all) do
    @server.kill_server
  end

  let(:client) { NATS.connect("nats://127.0.0.1:4522") }
  let(:errors) { Queue.new }
  let(:stops) { Queue.new }

  let(:service) do
    client.services.add(
      name: "errs",
      version: "1.0.0",
      error_handler: ->(svc, err) { errors << [svc, err] }
    )
  end

  before { service.on_stop { |error| stops << error } }

  after { client.close unless client.closed? }

  def pop(queue, timeout = 2)
    Timeout.timeout(timeout) { queue.pop }
  end

  context "when a NATS error is raised in an endpoint handler" do
    let!(:endpoint) do
      service.endpoints.add("fail") { |_req| raise NATS::IO::ServerError, "boom" }
    end

    it "calls the error handler with a NATSError and stops the service" do
      expect { client.request("fail", "", timeout: 0.2) }.to raise_error(NATS::Timeout)

      svc, err = pop(errors)
      expect(svc).to be(service)
      expect(err).to be_a(NATS::Service::NATSError)
      expect(err).to have_attributes(subject: "fail", description: "boom")
      expect(err.error).to be_a(NATS::IO::ServerError)
      expect(err.message).to eq('"fail": boom')

      expect(pop(stops)).to be_a(NATS::IO::ServerError)
      expect(service.stopped?).to be(true)
      expect(endpoint.stats.num_errors).to eq(1)
      expect(endpoint.stats.last_error).to eq("500:boom")
    end

    it "still reports the error to the client's error callback" do
      client_errors = Queue.new
      client.on_error { |e| client_errors << e }

      expect { client.request("fail", "", timeout: 0.2) }.to raise_error(NATS::Timeout)

      expect(pop(client_errors)).to be_a(NATS::IO::ServerError)
    end
  end

  context "when another exception is raised in an endpoint handler" do
    before do
      service.endpoints.add("oops") { |_req| raise "oops" }
    end

    it "responds with a 500 and keeps the service running" do
      resp = client.request("oops", "")

      expect(resp.header).to eq(
        "Nats-Service-Error" => "oops",
        "Nats-Service-Error-Code" => "500"
      )
      expect(service.stopped?).to be(false)
      expect(errors).to be_empty
    end
  end

  context "when an endpoint is a slow consumer" do
    it "calls the error handler and stops the service" do
      gate = Queue.new
      endpoint = service.endpoints.add("slow") { |_req| gate.pop }
      endpoint.subscription.pending_msgs_limit = 1

      5.times { client.publish("slow", "x") }
      client.flush

      svc, err = pop(errors)
      expect(svc).to be(service)
      expect(err).to have_attributes(subject: "slow")
      expect(err.error).to be_a(NATS::IO::SlowConsumer)
      expect(err.description).to include("slow consumer")

      pop(stops)
      expect(service.stopped?).to be(true)
      expect(endpoint.stats.num_errors).to be >= 1

      5.times { gate << true }
    end
  end

  context "when a subscription outside the service fails" do
    it "does not stop the service" do
      service.endpoints.add("ok") { |req| req.respond("ok") }
      client.subscribe("other") { raise NATS::IO::ServerError }

      client.publish("other", "")
      client.flush
      sleep 0.2

      expect(errors).to be_empty
      expect(service.stopped?).to be(false)
      expect(client.request("ok", "").data).to eq("ok")
    end
  end

  context "when the connection is closed" do
    it "stops the service" do
      service.endpoints.add("ok") { |req| req.respond("ok") }
      other = client.services.add(name: "other", version: "1.0.0")

      client.close

      expect(pop(stops)).to be_nil
      expect(service.stopped?).to be(true)
      expect(other.stopped?).to be(true)
      expect(service.endpoints.all?(&:stopped?)).to be(true)
      expect(service.monitoring.stopped?).to be(true)
    end
  end

  context "with an on_error block" do
    let(:service) { client.services.add(name: "errs", version: "1.0.0") }

    it "registers the error handler" do
      service.on_error { |svc, err| errors << [svc, err] }
      service.endpoints.add("fail") { |_req| raise NATS::IO::ServerError, "boom" }

      client.publish("fail", "")

      _, err = pop(errors)
      expect(err).to eq(NATS::Service::NATSError.new("fail", "boom"))
    end
  end

  describe NATS::Service::NATSError do
    it "compares by subject and description" do
      a = described_class.new("a", "x", RuntimeError.new("x"))

      expect(a).to eq(described_class.new("a", "x"))
      expect(a).not_to eq(described_class.new("b", "x"))
      expect(a).to be_a(NATS::Service::Error)
      expect(a.message).to eq('"a": x')
    end
  end
end

# frozen_string_literal: true

RSpec.describe "Service respond errors" do
  before(:all) do
    @server = NatsServerControl.new("nats://127.0.0.1:4544", "/tmp/test-nats.pid", "")
    @server.start_server(true)
  end

  after(:all) do
    @server.kill_server
  end

  let(:client) do
    NATS.connect("nats://127.0.0.1:4544").tap { |nc| nc.on_error { |_e| nil } }
  end
  let(:handler_errors) { Queue.new }
  let(:service) do
    client.services.add(name: "errs", version: "1.0.0", error_handler: ->(_svc, err) { handler_errors << err })
  end

  after { client.close }

  describe "respond_with_error" do
    def error_raised_for(error)
      raised = Queue.new
      subject = "e#{service.endpoints.count}"
      service.endpoints.add(subject) do |req|
        req.respond_with_error(error)
      rescue => e
        raised << e
      end
      expect { client.request(subject, "", timeout: 0.3) }.to raise_error(NATS::Timeout)
      raised.pop(timeout: 1)
    end

    it "raises ArgRequiredError without a code, and sends nothing" do
      [{code: "", description: "bad"}, {code: nil, description: "bad"}, {description: "bad"}].each do |error|
        err = error_raised_for(error)
        expect(err).to be_a(NATS::Service::ArgRequiredError)
        expect(err).to be_a(NATS::Service::Error)
        expect(err.message).to eq("argument required: error code")
      end
    end

    it "raises ArgRequiredError without a description, and sends nothing" do
      [{code: 400, description: ""}, {code: 400}, ""].each do |error|
        err = error_raised_for(error)
        expect(err).to be_a(NATS::Service::ArgRequiredError)
        expect(err.message).to eq("argument required: description")
      end
    end

    it "names an error that has an empty message by its class" do
      service.endpoints.add("raise") { |_req| raise ArgumentError, "" }

      resp = client.request("raise", "")
      expect(resp.header).to include(NATS::Service::ERROR_HEADER => "ArgumentError", NATS::Service::ERROR_CODE_HEADER => "500")
    end
  end

  describe "respond" do
    it "raises RespondError with the error of the client as its cause" do
      raised = Queue.new
      endpoint = service.endpoints.add("noreply") do |req|
        req.respond("ok")
      rescue => e
        raised << e
      end

      # Without a reply subject, the response cannot be sent.
      client.publish("noreply", "")
      err = raised.pop(timeout: 2)

      expect(err).to be_a(NATS::Service::RespondError)
      expect(err).to be_a(NATS::Service::Error)
      expect(err.message).to start_with("NATS error when sending response: ")
      expect(err.cause).to be_a(NATS::IO::BadSubject)

      # Rescued by the handler, it is counted, like in nats.go micro, and
      # the service goes on.
      wait_until { endpoint.stats.num_errors == 1 }
      expect(endpoint.stats.last_error).to start_with("500:NATS error when sending response")
      expect(service.stopped?).to be(false)
    end

    it "wraps the failures of respond_json and respond_with_error" do
      raised = Queue.new
      service.endpoints.add("json") do |req|
        req.respond_json({a: 1})
      rescue => e
        raised << e
      end
      service.endpoints.add("err") do |req|
        req.respond_with_error("bad")
      rescue => e
        raised << e
      end

      client.publish("json", "")
      client.publish("err", "")

      2.times do
        err = raised.pop(timeout: 2)
        expect(err).to be_a(NATS::Service::RespondError)
        expect(err.cause).to be_a(NATS::IO::BadSubject)
      end
    end

    it "stops the service when the handler does not rescue it" do
      endpoint = service.endpoints.add("unhandled") { |req| req.respond("ok") }

      client.publish("unhandled", "")

      err = handler_errors.pop(timeout: 2)
      expect(err).to be_a(NATS::Service::NATSError)
      expect(err.subject).to eq("unhandled")
      expect(err.error).to be_a(NATS::Service::RespondError)
      expect(err.error.cause).to be_a(NATS::IO::BadSubject)
      wait_until { service.stopped? }
      expect(endpoint.stats.num_errors).to eq(1)
    end
  end
end

# frozen_string_literal: true

RSpec.describe "Service endpoint pending limits" do
  before(:all) do
    @server = NatsServerControl.new("nats://127.0.0.1:4543", "/tmp/test-nats.pid", "")
    @server.start_server(true)
  end

  after(:all) do
    @server.kill_server
  end

  let(:client) do
    NATS.connect("nats://127.0.0.1:4543").tap do |nc|
      # Slow consumer errors are expected here.
      nc.on_error { |_e| nil }
    end
  end
  let(:errors) { Queue.new }
  let(:service) do
    client.services.add(name: "limited", version: "1.0.0", error_handler: ->(_svc, err) { errors << err })
  end

  after { client.close }

  it "sets the pending limits of the endpoint's subscription" do
    endpoint = service.endpoints.add("e", pending_msgs_limit: 10, pending_bytes_limit: 2048) {}

    expect(endpoint).to have_attributes(pending_msgs_limit: 10, pending_bytes_limit: 2048)
    expect(endpoint.subscription).to have_attributes(pending_msgs_limit: 10, pending_bytes_limit: 2048)
  end

  it "keeps the limits of the client for those not given" do
    endpoint = service.endpoints.add("e", pending_msgs_limit: 10) {}
    other = service.endpoints.add("f") {}

    expect(endpoint.pending_bytes_limit).to be_nil
    expect(endpoint.subscription).to have_attributes(
      pending_msgs_limit: 10, pending_bytes_limit: NATS::IO::DEFAULT_SUB_PENDING_BYTES_LIMIT
    )
    expect(other.subscription.pending_msgs_limit).to eq(NATS::IO::DEFAULT_SUB_PENDING_MSGS_LIMIT)
  end

  it "stops the service as a slow consumer once the messages limit is reached" do
    release = Queue.new
    endpoint = service.endpoints.add("slow", pending_msgs_limit: 2) { |_req| release.pop }

    10.times { client.publish("slow", "x") }
    client.flush

    error = errors.pop(timeout: 5)
    expect(error).to be_a(NATS::Service::NATSError)
    expect(error).to have_attributes(subject: "slow")
    expect(error.error).to be_a(NATS::IO::SlowConsumer)
    wait_until { service.stopped? }
    expect(endpoint.subscription.dropped).to be > 0
    expect(endpoint.stats.num_errors).to be >= 1
  ensure
    10.times { release << true }
  end

  it "stops the service as a slow consumer once the bytes limit is reached" do
    release = Queue.new
    service.endpoints.add("big", pending_bytes_limit: 100) { |_req| release.pop }

    5.times { client.publish("big", "x" * 60) }
    client.flush

    expect(errors.pop(timeout: 5).error).to be_a(NATS::IO::SlowConsumer)
    wait_until { service.stopped? }
  ensure
    5.times { release << true }
  end

  it "takes the limits for the default endpoint" do
    svc = client.services.add(
      name: "dflt", version: "1.0.0",
      endpoint: {subject: "dflt", pending_msgs_limit: 5, handler: ->(req) { req.respond("") }}
    )

    expect(svc.endpoints.first.subscription.pending_msgs_limit).to eq(5)
  end

  it "raises InvalidPendingLimitsError for a limit that is not a positive Integer" do
    [0, -1, 1.5, "10"].each do |limit|
      expect { service.endpoints.add("e", pending_msgs_limit: limit) {} }
        .to raise_error(NATS::Service::InvalidPendingLimitsError, /pending_msgs_limit/)
      expect { service.endpoints.add("e", pending_bytes_limit: limit) {} }
        .to raise_error(NATS::Service::InvalidPendingLimitsError, /pending_bytes_limit/)
    end
    expect(NATS::Service::InvalidPendingLimitsError.ancestors).to include(NATS::Service::Error)
    expect(service.endpoints.to_a).to be_empty
  end
end

# frozen_string_literal: true

RSpec.describe "Service queue group disabled" do
  before(:all) do
    @server = NatsServerControl.new("nats://127.0.0.1:4542", "/tmp/test-nats.pid", "")
    @server.start_server(true)
  end

  after(:all) do
    @server.kill_server
  end

  let(:client) { NATS.connect("nats://127.0.0.1:4542") }

  after { client.close }

  # Adds the endpoint to two instances of a service and returns how many
  # times their handlers were called for 10 requests.
  def handled(service_opts, endpoint_opts = {}, group: nil)
    calls = Queue.new
    services = 2.times.map { client.services.add(name: "svc", version: "1.0.0", **service_opts) }
    services.each do |service|
      parent = group ? service.groups.add(group[:name], **group.except(:name)) : service
      parent.endpoints.add("work", endpoint_opts) { |req| calls << req.subject }
    end
    client.flush

    10.times { client.publish(services.first.endpoints.first.subject, "x") }
    client.flush
    wait_until { calls.size >= 10 }
    # Gives the requests that every instance gets the time to arrive.
    sleep 0.2
    calls.size
  end

  it "subscribes in the default queue group" do
    expect(handled({})).to eq(10)
  end

  it "subscribes without a queue group when the service disables it" do
    expect(handled({queue_group_disabled: true})).to eq(20)

    service = client.services.to_a.first
    endpoint = service.endpoints.first
    expect(service.queue_group_disabled?).to be(true)
    expect(service.queue).to eq("")
    expect(endpoint.queue_group_disabled?).to be(true)
    expect(endpoint.queue).to eq("")
    expect(endpoint.subscription.queue).to be_nil

    info = JSON.parse(client.request("$SRV.INFO.svc.#{service.id}", "").data)
    expect(info["endpoints"].first["queue_group"]).to eq("")
    stats = JSON.parse(client.request("$SRV.STATS.svc.#{service.id}", "").data)
    expect(stats["endpoints"].first["queue_group"]).to eq("")
  end

  it "subscribes without a queue group when the endpoint disables it" do
    expect(handled({queue: "workers"}, {queue_group_disabled: true})).to eq(20)
    expect(client.services.to_a.first.endpoints.first).to have_attributes(queue: "", queue_group_disabled?: true)
  end

  it "subscribes without a queue group when the group disables it" do
    expect(handled({}, {}, group: {name: "g", queue_group_disabled: true})).to eq(20)

    service = client.services.to_a.first
    group = service.groups.first
    expect(group).to have_attributes(queue: "", queue_group_disabled?: true)
    expect(group.groups.add("nested")).to have_attributes(queue: "", queue_group_disabled?: true)
  end

  it "takes a queue group set below a disabled one" do
    expect(handled({queue_group_disabled: true}, {queue: "own"})).to eq(10)
    expect(client.services.to_a.first.endpoints.first).to have_attributes(queue: "own", queue_group_disabled?: false)

    service = client.services.add(name: "other", version: "1.0.0", queue_group_disabled: true)
    group = service.groups.add("g", queue: "grouped")
    expect(group).to have_attributes(queue: "grouped", queue_group_disabled?: false)
    expect(group.endpoints.add("e") {}).to have_attributes(queue: "grouped", queue_group_disabled?: false)
  end

  it "prefers the flag of the endpoint to its queue" do
    service = client.services.add(name: "flag", version: "1.0.0")
    endpoint = service.endpoints.add("e", queue: "own", queue_group_disabled: true) {}

    expect(endpoint).to have_attributes(queue: "", queue_group_disabled?: true)
  end

  it "still disables the queue group with a queue of an empty String" do
    expect(handled({queue: ""})).to eq(20)
    expect(client.services.to_a.first).to have_attributes(queue: "", queue_group_disabled?: true)
  end

  it "disables it for the default endpoint too" do
    service = client.services.add(
      name: "default", version: "1.0.0", queue: "workers",
      endpoint: {subject: "dflt", queue_group_disabled: true, handler: ->(req) { req.respond("") }}
    )

    expect(service.endpoints.first).to have_attributes(queue: "", queue_group_disabled?: true)
  end
end

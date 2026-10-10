# frozen_string_literal: true

describe "JetStream migration status" do
  before do
    @s = NatsServerControl.new("nats://127.0.0.1:4740", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after do
    @s.kill_server
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  # A cluster that changes to three replicas, as nats-server v2.15.0 sends
  # it while it waits for the replicas to catch up.
  let(:cluster) do
    {
      name: "C", leader: "n1", leader_since: "2026-01-02T00:00:00Z",
      replicas: [{name: "n2", current: true, active: 1_000_000, peer: "p2"}],
      desired: {
        created: "2026-01-03T00:00:00Z", name: "C",
        replicas: [{name: "n1", peer: "p1"}, {name: "n2", peer: "p2"}, {name: "n3", offline: true, peer: "p3"}],
        origin: {replicas: 1},
        status: {description: "waiting for desired peers to catch up", type: "catchup", err: "peer n3 offline"}
      }
    }
  end

  # Answers the JetStream API in place of a clustered server.
  def answer(subject, response)
    nc.subscribe(subject) { |msg| msg.respond(response.to_json) }
    nc.flush
  end

  it "has the types of nats.go MigrationStatusType" do
    expect(NATS::JetStream::API::MigrationStatus.constants.sort.to_h { |c| [c, NATS::JetStream::API::MigrationStatus.const_get(c)] }).to eql(
      BLOCKED: "blocked", CATCHUP: "catchup", MEMBERSHIP: "membership", META: "meta",
      QUORUM: "quorum", SNAPSHOT: "snapshot", UNAVAILABLE: "unavailable"
    )
  end

  it "reads the status of the desired cluster of a stream and a consumer" do
    answer("$JS.API.STREAM.INFO.S", {
      type: "io.nats.jetstream.api.v1.stream_info_response",
      config: {name: "S", subjects: ["s"]}, created: "2026-01-01T00:00:00Z",
      state: {messages: 0}, cluster: cluster
    })
    answer("$JS.API.CONSUMER.INFO.S.c", {
      type: "io.nats.jetstream.api.v1.consumer_info_response",
      stream_name: "S", name: "c", created: "2026-01-01T00:00:00Z",
      config: {durable_name: "c", ack_policy: "explicit"},
      delivered: {consumer_seq: 0, stream_seq: 0}, ack_floor: {consumer_seq: 0, stream_seq: 0},
      cluster: cluster
    })

    [js.stream_info("S").cluster, js.consumer_info("S", "c").cluster].each do |info|
      desired = info[:desired]
      expect(desired).to be_a(NATS::JetStream::API::DesiredClusterInfo)
      status = desired.status
      expect(status).to be_a(NATS::JetStream::API::DesiredClusterInfoStatus)
      expect(status.type).to eql(NATS::JetStream::API::MigrationStatus::CATCHUP)
      expect(status.description).to eql("waiting for desired peers to catch up")
      expect(status.err).to eql("peer n3 offline")
      # Still the Hash of the server.
      expect(desired[:status]).to eql(cluster[:desired][:status])
      expect(info).to eql(cluster)
    end
  end

  it "has no status while the desired cluster has none" do
    cluster[:desired].delete(:status)
    answer("$JS.API.STREAM.INFO.S", {
      type: "io.nats.jetstream.api.v1.stream_info_response",
      config: {name: "S"}, created: "2026-01-01T00:00:00Z", state: {messages: 0}, cluster: cluster
    })

    expect(js.stream_info("S").cluster[:desired].status).to be_nil
  end
end

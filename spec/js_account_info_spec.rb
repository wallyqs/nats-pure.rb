# frozen_string_literal: true

describe "JetStream account_info" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-account-info")
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }

  after { nc.close }

  describe "without tiers" do
    before do
      @s = NatsServerControl.new("nats://127.0.0.1:4746", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
      @s.start_server(true)
    end

    it "returns a typed AccountInfo" do
      nc.jsm.add_stream(name: "A", subjects: ["a"], storage: "memory")
      nc.jsm.add_consumer("A", durable_name: "c")
      nc.jetstream.publish("a", "hello")

      info = nc.jsm.account_info
      expect(info).to be_a(NATS::JetStream::API::AccountInfo)
      expect(info).to be_frozen
      expect(info.type).to eql("io.nats.jetstream.api.v1.account_info_response")
      expect(info.streams).to eql(1)
      expect(info.consumers).to eql(1)
      expect(info.memory).to be > 0
      expect(info.storage).to eql(0)
      expect(info.reserved_memory).to eql(0)
      expect(info.reserved_storage).to eql(0)
      expect(info.domain).to be_nil
      expect(info.tiers).to be_nil

      expect(info.limits).to be_a(NATS::JetStream::API::AccountLimits)
      expect(info.limits.to_h).to eql(
        max_memory: -1, max_storage: -1, max_streams: -1, max_consumers: -1, max_ack_pending: -1,
        memory_max_stream_bytes: -1, storage_max_stream_bytes: -1, max_bytes_required: false
      )

      expect(info.api).to be_a(NATS::JetStream::API::APIStats)
      expect(info.api.level).to be >= 1
      expect(info.api.total).to be >= 2
      expect(info.api.errors).to eql(0)
    end

    it "reads as the Hash it was" do
      info = nc.jsm.account_info(timeout: 2)
      expect(info[:streams]).to eql(0)
      expect(info[:limits][:max_streams]).to eql(-1)
      expect(info.dig(:api, :level)).to eql(info.api.level)
      expect(info.dig(:limits, :max_consumers)).to eql(-1)
      expect(info[:unknown]).to be_nil
      expect(info.dig(:tiers, :R1)).to be_nil

      # The Hash of the response, as the server sent it.
      raw = JSON.parse(nc.request("$JS.API.INFO").data, symbolize_names: true)
      hash = info.to_h
      expect(hash).to be_a(Hash)
      expect(hash.keys).to match_array(raw.keys)
      expect(hash[:limits]).to eql(raw[:limits])
      expect(hash[:api].keys).to match_array(raw[:api].keys)
      expect(hash[:api][:level]).to eql(raw[:api][:level])
    end

    it "takes the domain of the server" do
      @s.kill_server
      conf = File.join(@tmpdir, "domain.conf")
      File.write(conf, %(jetstream { store_dir: "#{@tmpdir}", domain: hub }))
      @s = NatsServerControl.new("nats://127.0.0.1:4746", "/tmp/test-nats.pid", "-c #{conf}")
      @s.start_server(true)

      info = nc.jetstream(domain: "hub").account_info
      expect(info.domain).to eql("hub")
      expect(info[:domain]).to eql("hub")
    end
  end

  describe "with tiers" do
    # Tiered limits take an operator; a responder of the JetStream API
    # sends the account info of a server with them instead.
    before do
      @s = NatsServerControl.new("nats://127.0.0.1:4747", "/tmp/test-nats.pid")
      @s.start_server(true)
      @api = NATS.connect(@s.uri)
      tier = {
        memory: 0, storage: 0, reserved_memory: 0, reserved_storage: 0, streams: 1, consumers: 0,
        limits: {max_memory: 1_048_576, max_storage: 2_097_152, max_streams: 3, max_consumers: 4,
                 max_ack_pending: -1, memory_max_stream_bytes: -1, storage_max_stream_bytes: -1, max_bytes_required: false}
      }
      resp = {
        type: "io.nats.jetstream.api.v1.account_info_response",
        memory: 0, storage: 0, reserved_memory: 0, reserved_storage: 0, streams: 1, consumers: 0,
        limits: {max_memory: 0, max_storage: 0, max_streams: 0, max_consumers: 0, max_ack_pending: 0,
                 memory_max_stream_bytes: 0, storage_max_stream_bytes: 0, max_bytes_required: false},
        api: {level: 3, total: 7, errors: 1},
        tiers: {R1: tier, R3: tier.merge(streams: 0)}
      }
      @api.subscribe("$JS.API.INFO") { |msg| msg.respond(resp.to_json) }
      @api.flush
    end

    after { @api.close }

    it "decodes the tiers" do
      info = nc.jsm.account_info
      expect(info.tiers.keys).to eql(["R1", "R3"])
      tier = info.tiers["R1"]
      expect(tier).to be_a(NATS::JetStream::API::Tier)
      expect(tier.streams).to eql(1)
      expect(info.tiers["R3"].streams).to eql(0)
      expect(tier.limits.max_memory).to eql(1024 * 1024)
      expect(tier.limits.max_storage).to eql(2 * 1024 * 1024)
      expect(tier.limits.max_streams).to eql(3)
      expect(tier.limits.max_consumers).to eql(4)
      expect(info.api.to_h).to eql(level: 3, total: 7, errors: 1)
      expect(info.api.inflight).to be_nil

      # Tier names as Symbols too, as in the Hash it was.
      expect(info[:tiers][:R1]).to equal(tier)
      expect(info.dig(:tiers, :R1, :limits, :max_streams)).to eql(3)
      expect(info.to_h[:tiers][:R1][:limits][:max_consumers]).to eql(4)
      expect(info.to_h[:tiers].keys).to eql([:R1, :R3])
    end
  end
end

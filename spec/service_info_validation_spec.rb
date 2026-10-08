# frozen_string_literal: true

RSpec.describe "Service info, stats, ping and validation" do
  before(:all) do
    @server = NatsServerControl.new("nats://127.0.0.1:4545", "/tmp/test-nats.pid", "")
    @server.start_server(true)
  end

  after(:all) do
    @server.kill_server
  end

  let(:client) { NATS.connect("nats://127.0.0.1:4545") }
  let(:service) { client.services.add(name: "calc", version: "1.2.3", metadata: {"k" => "v"}) }

  after { client.close }

  def monitor(verb)
    JSON.parse(client.request(NATS::Service.control_subject(verb, "calc", service.id), "").data, symbolize_names: true)
  end

  describe "types" do
    it "names the types of the responses like nats.go micro" do
      expect(NATS::Service::PING_RESPONSE_TYPE).to eq("io.nats.micro.v1.ping_response")
      expect(NATS::Service::INFO_RESPONSE_TYPE).to eq("io.nats.micro.v1.info_response")
      expect(NATS::Service::STATS_RESPONSE_TYPE).to eq("io.nats.micro.v1.stats_response")
    end

    it "gives info and stats their type, as the monitoring responses have it" do
      service.endpoints.add("add") { |req| req.respond("") }

      expect(service.info[:type]).to eq(NATS::Service::INFO_RESPONSE_TYPE)
      expect(service.stats[:type]).to eq(NATS::Service::STATS_RESPONSE_TYPE)
      expect(JSON.parse(service.info.to_json, symbolize_names: true)).to eq(monitor(:info))
      expect(monitor(:stats)[:type]).to eq(NATS::Service::STATS_RESPONSE_TYPE)
    end

    it "returns the ping response" do
      expect(service.ping).to eq(
        type: NATS::Service::PING_RESPONSE_TYPE, name: "calc", id: service.id, version: "1.2.3", metadata: {"k" => "v"}
      )
      expect(JSON.parse(service.ping.to_json, symbolize_names: true)).to eq(monitor(:ping))
    end
  end

  describe "#reset" do
    it "resets the started time with the stats" do
      endpoint = service.endpoints.add("add") { |req| req.respond("") }
      client.request("add", "")
      wait_until { endpoint.stats.num_requests == 1 }
      started = service.status.started_at

      sleep 1.1
      service.reset

      expect(service.status.started_at).to be > started
      expect(Time.iso8601(service.stats[:started])).to be > started.utc.floor
      expect(service.stats[:endpoints].first[:num_requests]).to eq(0)
      expect(monitor(:stats)[:started]).to eq(service.stats[:started])
    end
  end

  describe "validation" do
    it "requires a name" do
      expect { client.services.add(version: "1.0.0") }
        .to raise_error(NATS::Service::InvalidNameError, /invalid name nil: it should not be empty/)
      expect { client.services.add(name: "", version: "1.0.0") }.to raise_error(NATS::Service::InvalidNameError)
    end

    it "requires the whole name to match" do
      ["calc.v2", "$calc", "calc\nother", "with space", "calc*"].each do |name|
        expect { client.services.add(name: name, version: "1.0.0") }.to raise_error(NATS::Service::InvalidNameError)
      end
      expect(client.services.add(name: "Calc_v2-x", version: "1.0.0").name).to eq("Calc_v2-x")
    end

    it "requires a SemVer version" do
      expect { client.services.add(name: "calc") }
        .to raise_error(NATS::Service::InvalidVersionError, /invalid version nil: it should not be empty/)
      ["", "1.0", "v1.0.0", "1.0.0\nx", "01.0.0"].each do |version|
        expect { client.services.add(name: "calc", version: version) }.to raise_error(NATS::Service::InvalidVersionError)
      end
      expect(client.services.add(name: "calc", version: "1.0.0-rc.1+build.5").version).to eq("1.0.0-rc.1+build.5")
    end

    it "creates nothing for an invalid service" do
      expect { client.services.add(name: "calc") }.to raise_error(NATS::Service::InvalidVersionError)

      expect(client.services.to_a).to be_empty
      expect { client.request("$SRV.PING.calc", "", timeout: 0.2) }.to raise_error(NATS::IO::NoRespondersError)
    end

    it "requires the whole endpoint name to match" do
      expect { service.endpoints.add("add.v2") {} }.to raise_error(NATS::Service::InvalidNameError)
      expect(service.endpoints.add("add", subject: "add.v2") {}.subject).to eq("add.v2")
    end

    it "still takes group names that are subject prefixes" do
      expect(service.groups.add("math.v2").subject).to eq("math.v2")
      expect { service.groups.add("$%^&") }.to raise_error(NATS::Service::InvalidNameError)
    end
  end
end

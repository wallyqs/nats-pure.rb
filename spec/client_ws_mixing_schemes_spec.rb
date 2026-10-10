# frozen_string_literal: true

describe "Client - mixing websocket and other URLs" do
  before(:all) do
    @server = NatsServerControl.new("nats://127.0.0.1:4940", "/tmp/test-nats-4940.pid", "-a 127.0.0.1")
    @server.start_server(true)
  end

  after(:all) { @server.kill_server }

  let(:message) { "nats: mixing of websocket and non websocket URLs is not allowed" }

  it "should reject a server list that mixes them, like ErrMixingWebsocketSchemes of nats.go" do
    [
      ["nats://127.0.0.1:4940", "ws://127.0.0.1:8080"],
      ["ws://127.0.0.1:8080", "nats://127.0.0.1:4940"],
      ["tls://127.0.0.1:4940", "wss://127.0.0.1:8443"],
      ["wss://127.0.0.1:8443", "nats://127.0.0.1:4940"]
    ].each do |servers|
      expect do
        NATS.connect(servers: servers, reconnect: false, dont_randomize_servers: true)
      end.to raise_error(NATS::IO::MixingWebsocketSchemes, message)
    end
  end

  it "should reject comma separated URLs that mix them" do
    expect do
      NATS.connect("nats://127.0.0.1:4940, ws://127.0.0.1:8080", reconnect: false)
    end.to raise_error(NATS::IO::MixingWebsocketSchemes, message)
    expect do
      NATS::IO::Client.new("wss://127.0.0.1:8443,tls://127.0.0.1:4940")
    end.to raise_error(NATS::IO::MixingWebsocketSchemes)
  end

  it "should keep raising an ArgumentError, as before" do
    expect(NATS::IO::MixingWebsocketSchemes.ancestors).to include(ArgumentError)
    expect do
      NATS::IO::Client.new(nil, servers: ["nats://127.0.0.1:4940", "ws://127.0.0.1:8080"])
    end.to raise_error(ArgumentError, message)
  end

  it "should take websocket URLs together, and other URLs together" do
    expect { NATS::IO::Client.new(nil, servers: ["ws://127.0.0.1:8080", "wss://127.0.0.1:8443"]) }.not_to raise_error
    expect { NATS::IO::Client.new("nats://127.0.0.1:4940,tls://127.0.0.1:4941,127.0.0.1:4942") }.not_to raise_error

    nc = NATS.connect(servers: ["nats://127.0.0.1:4940", "nats://127.0.0.1:4941"], reconnect: false,
      dont_randomize_servers: true)
    expect(nc.connected?).to eql(true)
    nc.close
  end

  it "should raise the same error from set_server_pool" do
    nc = NATS.connect("nats://127.0.0.1:4940", reconnect: false)
    expect do
      nc.set_server_pool(["ws://127.0.0.1:8080"])
    end.to raise_error(NATS::IO::MixingWebsocketSchemes, message)
    expect do
      nc.set_server_pool(["nats://127.0.0.1:4940", "wss://127.0.0.1:8443"])
    end.to raise_error(NATS::IO::MixingWebsocketSchemes, message)
    nc.close
  end
end

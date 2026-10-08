# frozen_string_literal: true

require "tmpdir"

describe "Client - connected domain and system account" do
  before(:all) do
    @tmpdir = Dir.mktmpdir("nats-domain")
    config = %(
      net: "127.0.0.1"
      port: 4930
      jetstream { store_dir: "#{@tmpdir}", domain: "hub" }
      accounts {
        SYS: { users: [{user: "sys", password: "sys"}] }
        APP: { users: [{user: "app", password: "app"}], jetstream: enabled }
      }
      system_account: SYS
    )
    opts = {"pid_file" => "/tmp/test-nats-4930.pid", "host" => "127.0.0.1", "port" => 4930}
    @server = NatsServerControl.init_with_config_from_string(config, opts).tap(&:start_server)

    @plain = NatsServerControl.new("nats://127.0.0.1:4931", "/tmp/test-nats-4931.pid", "-a 127.0.0.1")
    @plain.start_server(true)
  end

  after(:all) do
    [@server, @plain].each(&:kill_server)
    FileUtils.rm_rf(@tmpdir)
  end

  it "should report the JetStream domain of the server, like ConnectedDomain" do
    nc = NATS.connect("nats://app:app@127.0.0.1:4930", reconnect: false)
    expect(nc.connected_domain).to eql("hub")
    expect(nc.connected_domain).to eql(nc.server_info[:domain])
    nc.close
    expect(nc.connected_domain).to be_nil

    nc = NATS.connect("nats://127.0.0.1:4931", reconnect: false)
    expect(nc.connected_domain).to be_nil
    nc.close
  end

  it "should tell whether the account is the system account, like IsSystemAccount" do
    nc = NATS.connect("nats://sys:sys@127.0.0.1:4930", reconnect: false)
    # The server tells it in the INFO that follows the connect.
    wait_until(timeout: 2) { nc.system_account? }
    expect(nc.system_account?).to eql(true)
    nc.close
    expect(nc.system_account?).to eql(false)

    nc = NATS.connect("nats://app:app@127.0.0.1:4930", reconnect: false)
    nc.flush
    wait_until(timeout: 2) { nc.server_info.key?(:connect_info) }
    expect(nc.system_account?).to eql(false)
    nc.close
  end
end

# frozen_string_literal: true

require "tmpdir"

describe "Client - connection introspection" do
  before(:all) do
    @tmpdir = Dir.mktmpdir("nats-introspection")
    @s = NatsServerControl.new("nats://127.0.0.1:4864", "/tmp/test-nats.pid",
      "-js -sd=#{@tmpdir} --name intro-srv -a 127.0.0.1")
    @s.start_server(true)
    @cs = NatsServerControl.new("nats://127.0.0.1:4865", "/tmp/test-nats.pid",
      "--name intro-clustered --cluster_name intro-cluster --cluster nats://127.0.0.1:4867")
    @cs.start_server(true)
    @auth = NatsServerControl.new("nats://user:s3cr3t@127.0.0.1:4866", "/tmp/test-nats.pid")
    @auth.start_server(true)
  end

  after(:all) do
    [@s, @cs, @auth].each(&:kill_server)
    FileUtils.rm_rf(@tmpdir)
  end

  it "should report the addresses of the connection" do
    nc = NATS.connect(@s.uri)

    expect(nc.connected_addr).to eql("127.0.0.1:4864")
    host, port = nc.local_addr.split(":")
    expect(host).to eql("127.0.0.1")
    expect(port.to_i).to be > 0
    expect(port.to_i).not_to eql(4864)

    nc.close
    expect(nc.connected_addr).to be_nil
    expect(nc.local_addr).to be_nil
  end

  it "should report what the server tells about itself and the connection" do
    nc = NATS.connect(@s.uri)

    expect(nc.connected_server_id).to eql(nc.server_info[:server_id])
    expect(nc.connected_server_id).to match(/\AN[A-Z0-9]+\z/)
    expect(nc.connected_server_name).to eql("intro-srv")
    expect(nc.connected_server_version).to match(/\A\d+\.\d+\.\d+/)
    expect(nc.connected_cluster_name).to be_nil
    expect(nc.client_id).to be_a(Integer)
    expect(nc.client_id).to be > 0
    expect(nc.client_ip).to eql("127.0.0.1")
    expect(nc.max_payload).to eql(1024 * 1024)
    expect(nc.headers_supported?).to be(true)
    expect(nc.auth_required?).to be(false)
    expect(nc.tls_required?).to be(false)
    expect(nc.jetstream?).to be(true)

    nc.close
    expect(nc.connected_server_id).to be_nil
    expect(nc.connected_server_name).to be_nil
    expect(nc.connected_server_version).to be_nil
    expect { nc.client_id }.to raise_error(NATS::IO::ConnectionClosedError)
    expect { nc.client_ip }.to raise_error(NATS::IO::ConnectionClosedError)
  end

  it "should report the cluster name of the server" do
    nc = NATS.connect(@cs.uri)

    expect(nc.connected_cluster_name).to eql("intro-cluster")
    expect(nc.connected_server_name).to eql("intro-clustered")
    expect(nc.jetstream?).to be(false)

    nc.close
  end

  it "should redact the password or token of the connected URL" do
    nc = NATS.connect(@auth.uri)
    expect(nc.auth_required?).to be(true)
    expect(nc.connected_url_redacted).to eql("nats://user:xxxxx@127.0.0.1:4866")
    # Not the URL of the connection itself.
    expect(nc.connected_server.password).to eql("s3cr3t")
    nc.close
    expect(nc.connected_url_redacted).to be_nil

    nc = NATS.connect(@s.uri)
    expect(nc.connected_url_redacted).to eql("nats://127.0.0.1:4864")
    nc.close
  end

  it "should redact the token of the connected URL" do
    token = NatsServerControl.new("nats://secret-token@127.0.0.1:4868", "/tmp/test-nats.pid")
    token.start_server(true)

    nc = NATS.connect(token.uri)
    expect(nc.connected_url_redacted).to eql("nats://xxxxx@127.0.0.1:4868")
    nc.close
  ensure
    token&.kill_server
  end

  it "should count the subscriptions" do
    nc = NATS.connect(@s.uri)
    expect(nc.num_subscriptions).to eql(0)

    sub = nc.subscribe("a") {}
    nc.subscribe("b")
    expect(nc.num_subscriptions).to eql(2)

    sub.unsubscribe
    expect(nc.num_subscriptions).to eql(1)

    # Like nats.go, the subscription of the responses to requests counts.
    nc.subscribe("svc") { |msg| msg.respond("ok") }
    nc.request("svc", "hi")
    expect(nc.num_subscriptions).to eql(3)

    nc.close
  end

  it "should report the bytes waiting to be sent" do
    s = NatsServerControl.new("nats://127.0.0.1:4869", "/tmp/test-nats.pid")
    s.start_server(true)
    nc = NATS.connect(s.uri, reconnect_time_wait: 10, max_reconnect_attempts: -1)
    nc.on_error {}
    nc.flush
    expect(nc.buffered).to eql(0)

    # Publishes are buffered while reconnecting.
    s.kill_server
    wait_until(timeout: 5) { nc.reconnecting? }
    nc.publish("foo", "hello")
    expect(nc.buffered).to eql("PUB foo  5\r\nhello\r\n".bytesize)

    nc.close
    expect { nc.buffered }.to raise_error(NATS::IO::ConnectionClosedError)
  ensure
    s&.kill_server
  end

  it "should return the callbacks that are set" do
    nc = NATS::IO::Client.new
    err_cb = proc { |e| e }
    close_cb = proc {}
    nc.on_error(&err_cb)
    nc.on_close(&close_cb)
    nc.on_lame_duck_mode(&close_cb)

    expect(nc.error_handler).to equal(err_cb)
    expect(nc.close_handler).to equal(close_cb)
    expect(nc.lame_duck_mode_handler).to equal(close_cb)
    expect(nc.connect_handler).to be_nil
    expect(nc.discovered_servers_handler).to be_nil
    expect(nc.disconnect_handler).to respond_to(:call)
    expect(nc.reconnect_handler).to respond_to(:call)
  end
end

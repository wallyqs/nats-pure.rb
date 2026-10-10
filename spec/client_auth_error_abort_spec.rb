# frozen_string_literal: true

require "tmpdir"

describe "Client - the same auth error twice aborts reconnecting" do
  let(:port) { 4805 }
  let(:url) { "nats://127.0.0.1:#{port}" }

  def write_config(token)
    File.write(@config, <<~CONF)
      net: "127.0.0.1"
      port: #{port}
      authorization { token: "#{token}" }
    CONF
  end

  before do
    @dir = Dir.mktmpdir
    @config = File.join(@dir, "auth.conf")
    write_config("first")
    @server = NatsServerControl.new(url, "/tmp/test-nats-auth-twice.pid", "-c #{@config}")
    @server.start_server(true)
  end

  after do
    @server.kill_server
    FileUtils.rm_rf(@dir)
  end

  # The server takes a new token, which drops the connection with an
  # authorization violation and refuses the old token.
  def rotate_token(token)
    write_config(token)
    Process.kill("HUP", @server.server_pid)
  end

  def connect(token, **opts)
    nc = NATS::IO::Client.new
    errors = Queue.new
    closed = Queue.new
    reconnected = Queue.new
    nc.on_error { |e| errors << e }
    nc.on_close { closed << true }
    nc.on_reconnect { reconnected << true }
    nc.connect(url, token_handler: -> { token.call }, reconnect_time_wait: 0.2, **opts)
    [nc, errors, closed, reconnected]
  end

  def drain(queue)
    Array.new(queue.size) { queue.pop }
  end

  it "closes the connection with infinite reconnects, like nats.go" do
    nc, errors, closed, = connect(-> { "first" }, max_reconnect_attempts: -1)
    rotate_token("second")

    # Once when the server drops the connection, and once when it refuses
    # the reconnect.
    expect(closed.pop(timeout: 10)).to be(true)
    expect(nc.closed?).to be(true)
    expect(nc.last_error).to be_a(NATS::IO::AuthorizationViolation)
    expect(drain(errors).grep(NATS::IO::AuthorizationViolation).size).to eql(2)
  end

  it "keeps reconnecting after a single auth error" do
    token = "first"
    nc, errors, closed, reconnected = connect(-> { token }, max_reconnect_attempts: -1)
    token = "second"
    rotate_token("second")

    expect(reconnected.pop(timeout: 10)).to be(true)
    expect(nc.connected?).to be(true)
    expect(drain(errors).grep(NATS::IO::AuthorizationViolation).size).to eql(1)

    # The successful reconnect clears the error of the server, so that a
    # single refusal again does not stop reconnecting either.
    token = "third"
    rotate_token("third")
    expect(reconnected.pop(timeout: 10)).to be(true)
    expect(nc.connected?).to be(true)
    expect(closed).to be_empty
    nc.close
  end

  it "keeps reconnecting with ignore_auth_error_abort" do
    token = "first"
    nc, errors, closed, reconnected = connect(-> { token }, max_reconnect_attempts: -1, ignore_auth_error_abort: true)
    rotate_token("second")

    auth_errors = []
    Timeout.timeout(10) do
      auth_errors << errors.pop until auth_errors.grep(NATS::IO::AuthorizationViolation).size >= 4
    end
    expect(nc.reconnecting?).to be(true)

    token = "second"
    expect(reconnected.pop(timeout: 10)).to be(true)
    expect(closed).to be_empty
    nc.close
  end

  it "still gives up on a single server after its first auth error with limited reconnects" do
    nc, errors, closed, = connect(-> { "first" }, max_reconnect_attempts: 5)
    rotate_token("second")

    expect(closed.pop(timeout: 10)).to be(true)
    expect(nc.closed?).to be(true)
    expect(drain(errors).grep(NATS::IO::AuthorizationViolation)).not_to be_empty
  end
end

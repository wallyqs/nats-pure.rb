# frozen_string_literal: true

require "tmpdir"

describe "Client - ignore_auth_error_abort" do
  let(:port) { 4804 }
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
    @server = NatsServerControl.new(url, "/tmp/test-nats-auth-abort.pid", "-c #{@config}")
    @server.start_server(true)
  end

  after do
    @server.kill_server
    FileUtils.rm_rf(@dir)
  end

  # The server takes a new token, which drops the connection with an
  # authorization violation and refuses the token of the client.
  def rotate_token
    write_config("second")
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
    nc.connect(url, token_handler: -> { token.call }, reconnect_time_wait: 0.2, max_reconnect_attempts: 30, **opts)
    [nc, errors, closed, reconnected]
  end

  it "gives up on the server after an authorization error by default" do
    nc, errors, closed, = connect(-> { "first" })
    rotate_token

    Timeout.timeout(10) { closed.pop }
    expect(nc.closed?).to be(true)
    auth_errors = []
    auth_errors << errors.pop until errors.empty?
    expect(auth_errors.grep(NATS::IO::AuthorizationViolation).size).to be >= 1
  end

  it "keeps reconnecting after repeated authorization errors, like nats.go" do
    token = "first"
    nc, errors, closed, reconnected = connect(-> { token }, ignore_auth_error_abort: true)
    rotate_token

    # The same error, again and again, while the client has the old token.
    auth_errors = []
    Timeout.timeout(10) do
      auth_errors << errors.pop until auth_errors.grep(NATS::IO::AuthorizationViolation).size >= 3
    end
    expect(nc.closed?).to be(false)
    expect(nc.reconnecting?).to be(true)

    token = "second"
    Timeout.timeout(10) { reconnected.pop }
    expect(nc.connected?).to be(true)
    expect(closed).to be_empty
    nc.close
  end
end

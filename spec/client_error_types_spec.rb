# frozen_string_literal: true

describe "Client - error types" do
  def start_server_with(port, config)
    opts = {"pid_file" => "/tmp/test-nats-#{port}.pid", "host" => "127.0.0.1", "port" => port}
    NatsServerControl.init_with_config_from_string(%(
      net: "127.0.0.1"
      port: #{port}
      #{config}
    ), opts).tap(&:start_server)
  end

  def connect_collecting_errors(uri, **opts)
    errors = []
    nc = NATS::IO::Client.new
    nc.on_error { |e| errors << e }
    nc.connect(uri, **opts)
    [nc, errors]
  end

  context "with permissions" do
    after do
      @s.kill_server
    end

    [true, false].each do |auth_required|
      it "should report a PermissionViolation and stay connected#{" when the server requires auth" if auth_required}" do
        @s = start_server_with(4950, %(
          authorization { users = [{user: a, password: a, permissions: {publish: {deny: ["forbidden"]}, subscribe: {deny: ["nosub"]}}}] }
          #{"no_auth_user: a" unless auth_required}
        ))
        reconnected = false
        nc, errors = connect_collecting_errors(auth_required ? "nats://a:a@127.0.0.1:4950" : "nats://127.0.0.1:4950")
        nc.on_reconnect { reconnected = true }

        nc.publish("forbidden", "x")
        nc.flush
        wait_until(timeout: 2) { errors.size == 1 }

        nc.subscribe("nosub") {}
        nc.flush
        wait_until(timeout: 2) { errors.size == 2 }

        expect(errors).to all(be_a(NATS::IO::PermissionViolation))
        expect(errors).to all(be_a(NATS::IO::ServerError))
        expect(errors.first.message).to match(/Permissions Violation for Publish to "forbidden"/)
        expect(nc.last_error).to be_a(NATS::IO::PermissionViolation)

        # Unlike other errors from the server, it does not drop the connection.
        nc.publish("allowed", "x")
        nc.flush
        expect(nc).to be_connected
        expect(reconnected).to be(false)
        expect(nc.stats[:reconnects]).to eql(0)
        nc.close
      end
    end
  end

  context "with limits" do
    before do
      @s = start_server_with(4951, %(
        max_connections: 1
        max_subscriptions: 1
        max_payload: 1024
      ))
    end

    after do
      @s.kill_server
    end

    it "should raise MaxConnectionsExceeded" do
      nc = NATS.connect(@s.uri)
      expect do
        NATS.connect(@s.uri, reconnect: false)
      end.to raise_error(NATS::IO::MaxConnectionsExceeded, /maximum connections exceeded/)
      expect(NATS::IO::MaxConnectionsExceeded.ancestors).to include(NATS::IO::ServerError)
      nc.close
    end

    it "should report MaxSubscriptionsExceeded and stay connected" do
      nc, errors = connect_collecting_errors(@s.uri)
      nc.subscribe("one") {}
      nc.subscribe("two") {}
      nc.flush
      wait_until(timeout: 2) { errors.size == 1 }
      expect(errors.first).to be_a(NATS::IO::MaxSubscriptionsExceeded)
      expect(nc).to be_connected
      nc.flush
      nc.close
    end

    it "should raise MaxPayload for messages larger than max_payload" do
      nc, errors = connect_collecting_errors(@s.uri)
      expect(nc.server_info[:max_payload]).to eql(1024)

      expect { nc.publish("big", "a" * 1025) }.to raise_error(NATS::IO::MaxPayload, /maximum payload exceeded/)
      # Headers count too.
      expect do
        nc.publish_msg(NATS::Msg.new(subject: "big", data: "a" * 1000, header: {"foo" => "a" * 40}))
      end.to raise_error(NATS::IO::MaxPayload)
      expect { nc.request("big", "a" * 1025) }.to raise_error(NATS::IO::MaxPayload)

      # Nothing was sent, so the connection is still up.
      nc.publish("big", "a" * 1024)
      nc.flush
      expect(nc).to be_connected
      expect(errors).to be_empty
      nc.close
    end
  end

  context "with a nats-server" do
    before do
      @s = NatsServerControl.new("nats://127.0.0.1:4952", "/tmp/test-nats.pid", "--user a --pass a")
      @s.start_server(true)
    end

    after do
      @s.kill_server
    end

    it "should raise AuthorizationViolation for wrong credentials" do
      expect do
        NATS.connect("nats://a:wrong@127.0.0.1:4952", reconnect: false)
      end.to raise_error(NATS::IO::AuthorizationViolation, /Authorization Violation/)
      expect(NATS::IO::AuthorizationViolation.ancestors).to include(NATS::IO::AuthError, NATS::IO::ConnectError)
    end

    it "should reject invalid subjects and queue names on subscribe" do
      nc = NATS.connect("nats://a:a@127.0.0.1:4952")
      ["", "foo bar", "foo\tbar", "foo\r\n"].each do |subject|
        expect { nc.subscribe(subject) {} }.to raise_error(NATS::IO::BadSubject)
      end
      expect { nc.subscribe("foo", queue: "bad queue") {} }.to raise_error(NATS::IO::BadQueueName)
      expect { nc.subscribe("foo.*.>", queue: "workers") {} }.not_to raise_error
      nc.flush
      expect(nc).to be_connected
      nc.close
    end

    it "should raise BadTimeout for a flush timeout that is not positive" do
      nc = NATS.connect("nats://a:a@127.0.0.1:4952")
      [0, -1, nil].each do |timeout|
        expect { nc.flush(timeout) }.to raise_error(NATS::IO::BadTimeout, /timeout invalid/)
      end
      # It is a Timeout, which a flush with a timeout of 0 used to raise.
      expect { nc.flush(0) }.to raise_error(NATS::Timeout)
      nc.flush(1)
      nc.close
    end

    it "should raise ConnectionReconnecting when draining while reconnecting" do
      closed = false
      nc = NATS::IO::Client.new
      nc.on_close { closed = true }
      nc.connect("nats://a:a@127.0.0.1:4952", reconnect_time_wait: 1, max_reconnect_attempts: -1)
      nc.flush

      @s.kill_server
      wait_until(timeout: 5) { nc.reconnecting? }
      expect { nc.drain }.to raise_error(NATS::IO::ConnectionReconnecting)
      wait_until(timeout: 5) { closed }
      expect(nc).to be_closed
    end

    it "should raise SecureConnWanted when the server does not support TLS" do
      expect do
        NATS.connect("tls://a:a@127.0.0.1:4952", reconnect: false)
      end.to raise_error(NATS::IO::SecureConnWanted)
    end
  end

  context "with a server without headers support" do
    before do
      @s = start_server_with(4953, "no_header_support: true")
    end

    after do
      @s.kill_server
    end

    it "should raise HeadersNotSupported" do
      nc = NATS.connect(@s.uri)
      expect(nc.server_info[:headers]).to be_falsey
      expect do
        nc.publish("hdr", "data", header: {"foo" => "bar"})
      end.to raise_error(NATS::IO::HeadersNotSupported, /headers not supported/)
      nc.publish("hdr", "data")
      nc.flush
      nc.close
    end
  end

  context "with a server that requires TLS" do
    before do
      @s = start_server_with(4954, %(
        tls {
          cert_file: "./spec/configs/certs/server.pem"
          key_file: "./spec/configs/certs/key.pem"
        }
      ))
    end

    after do
      @s.kill_server
    end

    it "should raise SecureConnRequired when the client does not use TLS" do
      expect do
        NATS.connect(@s.uri, reconnect: false)
      end.to raise_error(NATS::IO::SecureConnRequired)
      expect(NATS::IO::SecureConnRequired.ancestors).to include(NATS::IO::ConnectError)
    end
  end

  context "against a server that does not send INFO" do
    before(:all) do
      @fake_nats_server = TCPServer.new 4955
      @fake_nats_server_th = Thread.new do
        loop do
          client = @fake_nats_server.accept
          client.write "HELLO\r\n"
        rescue IOError
          break if @fake_nats_server.closed?
        end
      end
    end

    after(:all) do
      @fake_nats_server_th.exit
      @fake_nats_server.close
    end

    it "should raise NoInfoReceived" do
      expect do
        NATS.connect("nats://127.0.0.1:4955", reconnect: false)
      end.to raise_error(NATS::IO::NoInfoReceived)
    end
  end

  it "should map the errors of the server like nats.go" do
    nc = NATS::IO::Client.new
    {
      "'Stale Connection'" => NATS::IO::StaleConnectionError,
      "'Permissions Violation for Publish to \"foo\"'" => NATS::IO::PermissionViolation,
      "'maximum subscriptions exceeded'" => NATS::IO::MaxSubscriptionsExceeded,
      "'maximum connections exceeded'" => NATS::IO::MaxConnectionsExceeded,
      "'maximum account active connections exceeded'" => NATS::IO::MaxAccountConnectionsExceeded,
      "'Authorization Violation'" => NATS::IO::AuthorizationViolation,
      "'User Authentication Expired'" => NATS::IO::AuthenticationExpired,
      "'User Authentication Revoked'" => NATS::IO::AuthenticationRevoked,
      "'Account Authentication Expired'" => NATS::IO::AccountAuthenticationExpired
    }.each do |text, klass|
      [true, false].each do |auth_required|
        err = nc.send(:server_error_for, text, auth_required)
        expect(err).to be_an_instance_of(klass)
        expect(err.message).to eql(text)
      end
    end
    expect(NATS::IO::AuthenticationExpired.ancestors).to include(NATS::IO::AuthError)

    # Others stay generic.
    expect(nc.send(:server_error_for, "'Unknown Protocol Operation'", false)).to be_an_instance_of(NATS::IO::ServerError)
    expect(nc.send(:server_error_for, "'Unknown Protocol Operation'", true)).to be_an_instance_of(NATS::IO::AuthError)
  end
end

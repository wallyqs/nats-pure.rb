# frozen_string_literal: true

require "socket"

describe "Client - TLS connection state and errors" do
  let(:certs) { "./spec/configs/certs" }

  def start_tls_server(port, extra = "")
    config = %(
      net: "127.0.0.1"
      port: #{port}

      tls {
        cert_file: "./spec/configs/certs/server.pem"
        key_file:  "./spec/configs/certs/key.pem"
        ca_file:   "./spec/configs/certs/ca.pem"
        timeout:   5
        #{extra}
      }
    )
    opts = {"pid_file" => "/tmp/test-nats-#{port}.pid", "host" => "127.0.0.1", "port" => port}
    NatsServerControl.init_with_config_from_string(config, opts).tap(&:start_server)
  end

  # A TLS server that completes the handshake, after sending an INFO that
  # asks for TLS unless handshake_first, and then closes the connection,
  # like a proxy that rejects the client certificate.
  def start_closing_tls_server(handshake_first: false)
    tcp = TCPServer.new("127.0.0.1", 0)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.cert = OpenSSL::X509::Certificate.new(File.read("#{certs}/server.pem"))
    ctx.key = OpenSSL::PKey.read(File.read("#{certs}/key.pem"))
    thread = Thread.new do
      conn = tcp.accept
      unless handshake_first
        conn.write(%(INFO {"server_id":"test","host":"127.0.0.1","port":#{tcp.addr[1]},"tls_required":true,"max_payload":1048576}\r\n))
      end
      tls = OpenSSL::SSL::SSLSocket.new(conn, ctx)
      tls.sync_close = true
      tls.accept
      tls.close
    rescue
      nil
    end
    [tcp, thread]
  end

  context "with a server that requires TLS" do
    before(:all) { @server = start_tls_server(4910) }
    after(:all) { @server.kill_server }

    it "should report the TLS state of the connection" do
      nc = NATS.connect("tls://127.0.0.1:4910", reconnect: false, tls: {ca_file: "#{certs}/ca.pem"})
      state = nc.tls_connection_state
      expect(state).to be_a(NATS::IO::TLSConnectionState)
      expect(state.handshake_complete).to eql(true)
      expect(state.version).to match(/\ATLSv1\.[23]\z/)
      expect(state.cipher).to be_a(String)
      expect(state.server_name).to eql("127.0.0.1")
      expect(state.did_resume).to eql(false)
      expect(state.peer_certificates).not_to be_empty
      expect(state.peer_certificates.first).to be_a(OpenSSL::X509::Certificate)
      expect(state.peer_certificates.first.subject.to_s).to include("CN=localhost server")
      nc.close

      expect { nc.tls_connection_state }.to raise_error(NATS::IO::Disconnected)
    end

    it "should wrap a failed TLS handshake in a TLSError" do
      expect do
        NATS.connect("tls://127.0.0.1:4910", reconnect: false, tls: {ca_file: "#{certs}/bad-ca.pem"})
      end.to raise_error(NATS::IO::TLSError, /tls error: .*certificate verify failed/) { |e|
        expect(e).to be_a(NATS::IO::ConnectError)
        expect(e.cause).to be_a(OpenSSL::SSL::SSLError)
      }
    end

    it "should report the TLSError to on_error too" do
      errors = []
      nc = NATS::IO::Client.new
      nc.on_error { |e| errors << e }
      expect do
        nc.connect("tls://127.0.0.1:4910", reconnect: false, tls: {ca_file: "#{certs}/bad-ca.pem"})
      end.to raise_error(NATS::IO::TLSError)
      expect(errors.first).to be_a(NATS::IO::TLSError)
    end
  end

  context "with a server that verifies client certificates" do
    before(:all) { @server = start_tls_server(4911, "verify: true") }
    after(:all) { @server.kill_server }

    it "should fail with a TLSError when the server rejects the missing client certificate" do
      expect do
        NATS.connect("tls://127.0.0.1:4911", reconnect: false, tls: {ca_file: "#{certs}/ca.pem"})
      end.to raise_error(NATS::IO::TLSError) { |e|
        expect(e.cause).to be_a(OpenSSL::SSL::SSLError).or be_a(SystemCallError).or be_a(EOFError)
      }
    end
  end

  context "with a server that closes the connection after the TLS handshake" do
    it "should fail with a TLSError" do
      tcp, thread = start_closing_tls_server
      expect do
        NATS.connect("nats://127.0.0.1:#{tcp.addr[1]}", reconnect: false, tls: {ca_file: "#{certs}/ca.pem"})
      end.to raise_error(NATS::IO::TLSError, /closed by remote after TLS handshake/)
    ensure
      thread&.join(2)
      tcp&.close
    end

    it "should fail with a TLSError with tls_handshake_first" do
      tcp, thread = start_closing_tls_server(handshake_first: true)
      expect do
        NATS.connect("tls://127.0.0.1:#{tcp.addr[1]}", reconnect: false, tls_handshake_first: true,
          tls: {ca_file: "#{certs}/ca.pem"})
      end.to raise_error(NATS::IO::TLSError, /closed by remote after TLS handshake/) { |e|
        expect(e.cause).to be_a(EOFError).or be_a(SystemCallError).or be_a(OpenSSL::SSL::SSLError)
      }
    ensure
      thread&.join(2)
      tcp&.close
    end
  end

  context "with a server that does not use TLS" do
    before(:all) do
      @server = NatsServerControl.new("nats://127.0.0.1:4912", "/tmp/test-nats-4912.pid", "-a 127.0.0.1")
      @server.start_server(true)
    end

    after(:all) { @server.kill_server }

    it "should raise ConnectionNotTLS" do
      nc = NATS.connect("nats://127.0.0.1:4912", reconnect: false)
      expect { nc.tls_connection_state }.to raise_error(NATS::IO::ConnectionNotTLS, "nats: connection is not tls")
      nc.close
    end
  end
end

# frozen_string_literal: true

describe "Client - TLS options" do
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

  def round_trip(nc)
    msgs = []
    nc.subscribe("tls.opts") { |msg| msgs << msg.data }
    nc.publish("tls.opts", "hi")
    nc.flush
    wait_until(timeout: 2) { msgs == ["hi"] }
  end

  context "when the server verifies client certificates" do
    before(:all) { @server = start_tls_server(4900, "verify: true") }
    after(:all) { @server.kill_server }

    it "should connect with cert_file, key_file and ca_file" do
      nc = NATS.connect("tls://127.0.0.1:4900", reconnect: false, tls: {
        cert_file: "#{certs}/client-cert.pem",
        key_file: "#{certs}/client-key.pem",
        ca_file: "#{certs}/ca.pem"
      })
      round_trip(nc)
      nc.close
    end

    it "should connect to servers given as a list with tls://" do
      nc = NATS.connect(servers: ["tls://127.0.0.1:4900"], reconnect: false, tls: {
        cert_file: "#{certs}/client-cert.pem",
        key_file: "#{certs}/client-key.pem",
        ca_file: "#{certs}/ca.pem"
      })
      round_trip(nc)
      nc.close
    end

    it "should fail without a client certificate" do
      expect do
        nc = NATS.connect("tls://127.0.0.1:4900", reconnect: false, tls: {ca_file: "#{certs}/ca.pem"})
        nc.flush(1)
      end.to raise_error(StandardError)
    end
  end

  context "when the server does not verify client certificates" do
    before(:all) { @server = start_tls_server(4901) }
    after(:all) { @server.kill_server }

    it "should trust only the CAs in ca_file" do
      nc = NATS.connect("tls://127.0.0.1:4901", reconnect: false, tls: {ca_file: "#{certs}/ca.pem"})
      round_trip(nc)
      nc.close

      expect do
        NATS.connect("tls://127.0.0.1:4901", reconnect: false, tls: {ca_file: "#{certs}/bad-ca.pem"})
      end.to raise_error(NATS::IO::TLSError, /certificate verify failed/) { |e| expect(e.cause).to be_a(OpenSSL::SSL::SSLError) }
    end

    it "should use the default TLS context for servers given as a list with tls://" do
      # This used to fail with a TypeError, for want of a TLS context. Whether
      # the default context trusts the CA of the server depends on what
      # other specs added to OpenSSL's default certificate store.
      nc = NATS.connect(servers: ["tls://127.0.0.1:4901"], reconnect: false)
      expect(nc.instance_variable_get(:@io).socket).to be_a(OpenSSL::SSL::SSLSocket)
      nc.close
    rescue NATS::IO::TLSError => e
      expect(e.message).to match(/certificate verify failed/)
    end

    it "should fail to handshake first with a server that sends INFO first" do
      expect do
        NATS.connect("tls://127.0.0.1:4901", reconnect: false, tls_handshake_first: true,
          connect_timeout: 1, tls: {ca_file: "#{certs}/ca.pem"})
      end.to raise_error(StandardError)
    end
  end

  context "when the server expects the TLS handshake first" do
    before(:all) { @server = start_tls_server(4902, "handshake_first: true") }
    after(:all) { @server.kill_server }

    it "should connect with tls_handshake_first" do
      nc = NATS.connect("tls://127.0.0.1:4902", reconnect: false, tls_handshake_first: true,
        tls: {ca_file: "#{certs}/ca.pem"})
      round_trip(nc)
      nc.close
    end

    it "should connect with tls_handshake_first and a custom context" do
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.set_params
      ctx.cert_store = OpenSSL::X509::Store.new.tap { |store| store.add_file("#{certs}/ca.pem") }
      nc = NATS.connect(servers: ["nats://127.0.0.1:4902"], reconnect: false, tls_handshake_first: true,
        tls: {context: ctx})
      round_trip(nc)
      nc.close
    end

    it "should time out waiting for INFO without tls_handshake_first" do
      expect do
        NATS.connect("tls://127.0.0.1:4902", reconnect: false, connect_timeout: 0.5,
          tls: {ca_file: "#{certs}/ca.pem"})
      end.to raise_error(NATS::IO::SocketTimeoutError)
    end
  end

  context "with invalid options" do
    it "should reject a context together with certificate files" do
      ctx = OpenSSL::SSL::SSLContext.new
      expect do
        NATS::IO::Client.new("tls://127.0.0.1:4903", tls: {context: ctx, ca_file: "#{certs}/ca.pem"})
      end.to raise_error(ArgumentError, /ca_file/)
    end

    it "should reject cert_file without key_file" do
      expect do
        NATS::IO::Client.new("tls://127.0.0.1:4903", tls: {cert_file: "#{certs}/client-cert.pem"})
      end.to raise_error(ArgumentError, /cert_file and key_file/)
    end

    it "should fail on files that cannot be loaded" do
      expect do
        NATS::IO::Client.new("tls://127.0.0.1:4903", tls: {ca_file: "#{certs}/missing.pem"})
      end.to raise_error(OpenSSL::X509::StoreError)
    end
  end
end

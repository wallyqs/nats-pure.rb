# frozen_string_literal: true

describe "Client - TLS certificate and CA callbacks" do
  let(:certs) { "./spec/configs/certs" }
  let(:cert) { OpenSSL::X509::Certificate.new(File.read("#{certs}/client-cert.pem")) }
  let(:key) { OpenSSL::PKey.read(File.read("#{certs}/client-key.pem")) }
  let(:store) { OpenSSL::X509::Store.new.tap { |s| s.add_file("#{certs}/ca.pem") } }

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
    nc.subscribe("tls.cb") { |msg| msgs << msg.data }
    nc.publish("tls.cb", "hi")
    nc.flush
    wait_until(timeout: 2) { msgs == ["hi"] }
  end

  context "when the server verifies client certificates" do
    before(:all) { @server = start_tls_server(4920, "verify: true") }
    after(:all) { @server.kill_server }

    it "should connect with the certificate and CAs of the callbacks" do
      cert_calls = 0
      ca_calls = 0
      nc = NATS.connect("tls://127.0.0.1:4920", reconnect: false, tls: {
        cert_cb: -> { (cert_calls += 1) && [cert, key] },
        ca_cb: -> { (ca_calls += 1) && store }
      })
      round_trip(nc)
      expect(nc.tls_connection_state.peer_certificates.first.subject.to_s).to include("CN=localhost server")
      # Once to check them, like nats.go, and once for the connect.
      expect([cert_calls, ca_calls]).to eql([2, 2])
      nc.close
    end

    it "should take PEM and a cert_cb together with ca_file" do
      nc = NATS.connect("tls://127.0.0.1:4920", reconnect: false, tls: {
        cert_cb: -> { [File.read("#{certs}/client-cert.pem"), File.read("#{certs}/client-key.pem")] },
        ca_file: "#{certs}/ca.pem"
      })
      round_trip(nc)
      nc.close
    end

    it "should fail with a TLSError without a client certificate from ca_cb only" do
      expect do
        NATS.connect("tls://127.0.0.1:4920", reconnect: false, tls: {ca_cb: -> { store }})
      end.to raise_error(NATS::IO::TLSError)
    end

    it "should call the callbacks again on each reconnect" do
      cert_calls = 0
      ca_calls = 0
      reconnects = 0
      nc = NATS.connect("tls://127.0.0.1:4920", reconnect_time_wait: 0.1, reconnect_jitter_tls: 0,
        max_reconnect_attempts: -1, tls: {
          cert_cb: -> { (cert_calls += 1) && [cert, key] },
          ca_cb: -> { (ca_calls += 1) && store }
        })
      nc.on_reconnect { reconnects += 1 }
      expect([cert_calls, ca_calls]).to eql([2, 2])

      @server.kill_server
      @server.start_server(true)
      wait_until(timeout: 10) { reconnects == 1 }

      expect(cert_calls).to be >= 3
      expect(ca_calls).to be >= 3
      round_trip(nc)
      nc.close
    end
  end

  context "when the server does not verify client certificates" do
    before(:all) { @server = start_tls_server(4921) }
    after(:all) { @server.kill_server }

    it "should trust only the CAs of ca_cb" do
      nc = NATS.connect("tls://127.0.0.1:4921", reconnect: false, tls: {ca_cb: -> { store }})
      round_trip(nc)
      nc.close

      bad = OpenSSL::X509::Store.new.tap { |s| s.add_file("#{certs}/bad-ca.pem") }
      expect do
        NATS.connect("tls://127.0.0.1:4921", reconnect: false, tls: {ca_cb: -> { bad }})
      end.to raise_error(NATS::IO::TLSError, /certificate verify failed/)
    end

    it "should make a nats:// connection use TLS" do
      nc = NATS.connect("nats://127.0.0.1:4921", reconnect: false, tls: {ca_cb: -> { store }})
      expect(nc.tls_connection_state.handshake_complete).to eql(true)
      nc.close
    end
  end

  context "with invalid options" do
    let(:url) { "tls://127.0.0.1:4922" }

    it "should require a cert_cb or a ca_cb, like ClientTLSConfig of nats.go" do
      expect do
        NATS::IO::Client.new(url, tls: {cert_cb: nil, ca_cb: nil})
      end.to raise_error(NATS::IO::ClientCertOrRootCAsRequired, "nats: at least one of cert_cb or ca_cb must be set")
      expect(NATS::IO::ClientCertOrRootCAsRequired.ancestors).to include(ArgumentError)
    end

    it "should fail when a callback fails, without connecting" do
      expect do
        NATS::IO::Client.new(url, tls: {cert_cb: -> { raise IOError, "no cert" }})
      end.to raise_error(IOError, "no cert")
      expect do
        NATS::IO::Client.new(url, tls: {ca_cb: -> { "not a store" }})
      end.to raise_error(TypeError, /ca_cb/)
      expect do
        NATS::IO::Client.new(url, tls: {cert_cb: -> { [cert] }})
      end.to raise_error(TypeError, /cert_cb/)
      expect do
        NATS::IO::Client.new(url, tls: {cert_cb: "cert"})
      end.to raise_error(ArgumentError, /respond to call/)
    end

    it "should reject callbacks together with a context or the same files" do
      expect do
        NATS::IO::Client.new(url, tls: {context: OpenSSL::SSL::SSLContext.new, ca_cb: -> { store }})
      end.to raise_error(ArgumentError, /context cannot be combined with ca_cb/)
      expect do
        NATS::IO::Client.new(url, tls: {cert_cb: -> { [cert, key] }, cert_file: "#{certs}/client-cert.pem",
                                        key_file: "#{certs}/client-key.pem"})
      end.to raise_error(ArgumentError, /cert_cb cannot be combined with cert_file/)
      expect do
        NATS::IO::Client.new(url, tls: {ca_cb: -> { store }, ca_file: "#{certs}/ca.pem"})
      end.to raise_error(ArgumentError, /ca_cb cannot be combined with ca_file/)
    end
  end
end

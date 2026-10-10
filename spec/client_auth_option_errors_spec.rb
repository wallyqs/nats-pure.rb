# frozen_string_literal: true

describe "Client - auth option errors" do
  let(:url) { "nats://127.0.0.1:4916" }
  let(:sig_cb) { ->(nonce) { nonce } }

  before(:all) do
    @s = NatsServerControl.new("nats://127.0.0.1:4916", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
  end

  it "raises the named errors of nats.go for options that conflict" do
    {
      NATS::IO::TokenAlreadySet => [{auth_token: "secret", token_handler: -> { "secret" }}, "nats: token and token handler both set"],
      NATS::IO::UserInfoAlreadySet => [{user: "foo", user_info_handler: -> { %w[foo bar] }}, "nats: cannot set user info handler and user/pass"],
      NATS::IO::NkeyAndUser => [{user_jwt_cb: -> { "jwt" }, user_signature_cb: sig_cb, user_nkey_cb: -> { "UABC" }}, "nats: user callback and nkey defined"],
      NATS::IO::UserButNoSigCB => [{user_jwt_cb: -> { "jwt" }}, "nats: user callback defined without a signature handler"],
      NATS::IO::NkeyButNoSigCB => [{user_nkey_cb: -> { "UABC" }}, "nats: nkey defined without a signature handler"],
      NATS::IO::WebSocketHeadersAlreadySet => [{ws_headers: {"A" => "b"}, ws_headers_handler: -> { {} }}, "nats: websocket connection headers already set"]
    }.each do |klass, (opts, message)|
      expect { NATS.connect(url, opts.merge(reconnect: false)) }.to raise_error(klass, message)
    end
  end

  it "raises them for a token in the URL and for credentials with an nkey seed" do
    expect do
      NATS.connect("nats://secret@127.0.0.1:4916", token_handler: -> { "secret" })
    end.to raise_error(NATS::IO::TokenAlreadySet)

    expect do
      NATS.connect(url, user_credentials: "./spec/configs/nkeys/foo-user.creds", nkeys_seed: "./spec/configs/nkeys/foo-user.nk")
    end.to raise_error(NATS::IO::NkeyAndUser)
  end

  it "raises NoUserCB for a signature handler with nothing to sign for, like nats.go" do
    expect do
      NATS.connect(url, reconnect: false, user_signature_cb: sig_cb)
    end.to raise_error(NATS::IO::NoUserCB, "nats: user callback not defined")
    expect(NATS::IO::NoUserCB.ancestors).to include(ArgumentError)

    # Credentials sign for themselves; the client takes them without connecting.
    expect do
      NATS::IO::Client.new(url, user_signature_cb: sig_cb, user_credentials: "./spec/configs/nkeys/foo-user.creds")
    end.not_to raise_error
  end

  it "keeps them ArgumentErrors, as they were" do
    [
      NATS::IO::TokenAlreadySet, NATS::IO::UserInfoAlreadySet, NATS::IO::NkeyAndUser,
      NATS::IO::UserButNoSigCB, NATS::IO::NkeyButNoSigCB, NATS::IO::WebSocketHeadersAlreadySet
    ].each { |klass| expect(klass.ancestors).to include(ArgumentError) }

    expect do
      NATS.connect(url, user_nkey_cb: -> { "UABC" })
    end.to raise_error(ArgumentError, /nkey defined without a signature handler/)
  end

  it "connects when the options do not conflict" do
    nc = NATS.connect(url, reconnect: false, user_info_handler: -> { %w[foo bar] })
    nc.flush
    expect(nc).to be_connected
    nc.close
  end
end

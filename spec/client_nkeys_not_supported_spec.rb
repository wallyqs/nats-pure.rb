# frozen_string_literal: true

describe "Client - nkeys not supported" do
  let(:seed) { "./spec/configs/nkeys/foo-user.nk" }

  context "with a server that does not take nkeys" do
    before do
      @s = NatsServerControl.new("nats://127.0.0.1:4917", "/tmp/test-nats.pid")
      @s.start_server(true)
    end

    after do
      @s.kill_server
    end

    it "fails to connect with an nkey, as the server sends no nonce, like nats.go" do
      expect do
        NATS.connect("nats://127.0.0.1:4917", reconnect: false, nkeys_seed: seed)
      end.to raise_error(NATS::IO::NkeysNotSupported, "nats: nkeys not supported by the server")

      expect do
        NATS.connect("nats://127.0.0.1:4917", reconnect: false, user_nkey_cb: -> { "UABC" }, user_signature_cb: ->(nonce) { nonce })
      end.to raise_error(NATS::IO::NkeysNotSupported)
    end

    it "does not retry the server, which will not send a nonce either" do
      errors = []
      nc = NATS::IO::Client.new
      nc.on_error { |e| errors << e }
      started = NATS::MonotonicTime.now
      expect do
        nc.connect("nats://127.0.0.1:4917", reconnect_time_wait: 0.5, nkeys_seed: seed)
      end.to raise_error(NATS::IO::NkeysNotSupported)
      expect(NATS::MonotonicTime.since(started)).to be < 2
      expect(errors.map(&:class)).to eq([NATS::IO::NkeysNotSupported])
    end
  end

  context "with a server that takes nkeys" do
    before do
      @s = NatsServerControl.init_with_config_from_string(%(
        port = 4918
        authorization {
          users = [{nkey: "UCK5N7N66OBOINFXAYC2ACJQYFSOD4VYNU6APEJTAVFZB2SVHLKGEW7L"}]
        }
      ), {"pid_file" => "/tmp/nats_nkeys_not_supported.pid", "host" => "127.0.0.1", "port" => 4918})
      @s.start_server(true)
    end

    after do
      @s.kill_server
    end

    it "connects with the nkey" do
      nc = NATS.connect("nats://127.0.0.1:4918", reconnect: false, nkeys_seed: seed)
      nc.flush
      expect(nc).to be_connected
      nc.close
    end
  end
end

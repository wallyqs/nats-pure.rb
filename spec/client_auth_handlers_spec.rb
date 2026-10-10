# frozen_string_literal: true

describe "Client - auth handlers" do
  let(:creds_file) { "./spec/configs/nkeys/foo-user.creds" }

  context "with a token" do
    before do
      @s = NatsServerControl.new("nats://127.0.0.1:4910", "/tmp/test-nats.pid", "--auth secret")
      @s.start_server(true)
    end

    after do
      @s.kill_server
    end

    it "should call token_handler on every connect" do
      calls = 0
      reconnected = false
      nc = NATS::IO::Client.new
      nc.on_reconnect { reconnected = true }
      nc.connect("nats://127.0.0.1:4910", reconnect_time_wait: 0.1, token_handler: proc {
        calls += 1
        "secret"
      })
      nc.flush
      expect(calls).to eql(1)

      nc.force_reconnect
      wait_until(timeout: 5) { reconnected }
      nc.flush
      expect(calls).to eql(2)
      nc.close
    end

    it "should fail to connect with a wrong token from token_handler" do
      expect do
        NATS.connect("nats://127.0.0.1:4910", reconnect: false, token_handler: -> { "wrong" })
      end.to raise_error(NATS::IO::AuthError)
    end

    it "should reject token_handler together with a token" do
      expect do
        NATS.connect("nats://127.0.0.1:4910", auth_token: "secret", token_handler: -> { "secret" })
      end.to raise_error(ArgumentError, /token and token handler both set/)

      expect do
        NATS.connect("nats://secret@127.0.0.1:4910", token_handler: -> { "secret" })
      end.to raise_error(ArgumentError, /token and token handler both set/)

      expect do
        NATS.connect("nats://127.0.0.1:4910", token_handler: "secret")
      end.to raise_error(ArgumentError, /token_handler must respond to call/)
    end
  end

  context "with a user and password" do
    before do
      @s = NatsServerControl.new("nats://foo:bar@127.0.0.1:4912", "/tmp/test-nats.pid")
      @s.start_server(true)
    end

    after do
      @s.kill_server
    end

    it "should call user_info_handler on every connect" do
      calls = 0
      reconnected = false
      nc = NATS::IO::Client.new
      nc.on_reconnect { reconnected = true }
      nc.connect("nats://127.0.0.1:4912", reconnect_time_wait: 0.1, user_info_handler: proc {
        calls += 1
        ["foo", "bar"]
      })
      nc.flush
      expect(calls).to eql(1)

      nc.force_reconnect
      wait_until(timeout: 5) { reconnected }
      nc.flush
      expect(calls).to eql(2)
      nc.close
    end

    it "should prefer the user and password of the URL" do
      calls = 0
      nc = NATS.connect("nats://foo:bar@127.0.0.1:4912", user_info_handler: proc {
        calls += 1
        ["foo", "wrong"]
      })
      nc.flush
      expect(calls).to eql(0)
      nc.close
    end

    it "should fail to connect with wrong credentials from user_info_handler" do
      expect do
        NATS.connect("nats://127.0.0.1:4912", reconnect: false, user_info_handler: -> { ["foo", "wrong"] })
      end.to raise_error(NATS::IO::AuthError)
    end

    it "should reject user_info_handler together with user or pass" do
      expect do
        NATS.connect("nats://127.0.0.1:4912", user: "foo", pass: "bar", user_info_handler: -> { ["foo", "bar"] })
      end.to raise_error(ArgumentError, /cannot set user info handler and user\/pass/)
    end
  end

  context "with NKEYS and JWT" do
    before do
      config_opts = {
        "pid_file" => "/tmp/nats_nkeys_jwt.pid",
        "host" => "127.0.0.1",
        "port" => 4911
      }
      @s = NatsServerControl.init_with_config_from_string(%(
        authorization {
          timeout: 2
        }

        port = 4911
        operator = "./spec/configs/nkeys/op.jwt"

        # This is for account resolution.
        resolver = MEMORY

         # This is a map that can preload keys:jwts into a memory resolver.
         resolver_preload = {
           # foo
           AD7SEANS6BCBF6FHIB7SQ3UGJVPW53BXOALP75YXJBBXQL7EAFB6NJNA : "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJqdGkiOiIyUDNHU1BFSk9DNlVZNE5aM05DNzVQVFJIV1pVRFhPV1pLR0NLUDVPNjJYSlZESVEzQ0ZRIiwiaWF0IjoxNTUzODQwNjE1LCJpc3MiOiJPRFdJSUU3SjdOT1M3M1dWQk5WWTdIQ1dYVTRXWFdEQlNDVjRWSUtNNVk0TFhUT1Q1U1FQT0xXTCIsIm5hbWUiOiJmb28iLCJzdWIiOiJBRDdTRUFOUzZCQ0JGNkZISUI3U1EzVUdKVlBXNTNCWE9BTFA3NVlYSkJCWFFMN0VBRkI2TkpOQSIsInR5cGUiOiJhY2NvdW50IiwibmF0cyI6eyJsaW1pdHMiOnsic3VicyI6LTEsImNvbm4iOi0xLCJpbXBvcnRzIjotMSwiZXhwb3J0cyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwid2lsZGNhcmRzIjp0cnVlfX19.COiKg5EFK4Gb2gA7vtKHQK7vjMEUx-RMWYuN-Bg-uVOFs9GLwW7Dxc4TcN-poBGBEkwKnleiA9SjYO3y4-AqBQ"

           # bar
           AAXPTP32BD73YW3ACUY6DPXKWBSUW4VEZNE3LD4FUOFDP6KDU43PQVU2 : "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJqdGkiOiJPQ1dUQkRQTzVETjRSV0lFNEtJQ1BQWkszUEhHV0dQUVFKNFVET1pQSTVaRzJQUzZKVkpBIiwiaWF0IjoxNTUzODQwNjE5LCJpc3MiOiJPRFdJSUU3SjdOT1M3M1dWQk5WWTdIQ1dYVTRXWFdEQlNDVjRWSUtNNVk0TFhUT1Q1U1FQT0xXTCIsIm5hbWUiOiJiYXIiLCJzdWIiOiJBQVhQVFAzMkJENzNZVzNBQ1VZNkRQWEtXQlNVVzRWRVpORTNMRDRGVU9GRFA2S0RVNDNQUVZVMiIsInR5cGUiOiJhY2NvdW50IiwibmF0cyI6eyJsaW1pdHMiOnsic3VicyI6LTEsImNvbm4iOi0xLCJpbXBvcnRzIjotMSwiZXhwb3J0cyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwid2lsZGNhcmRzIjp0cnVlfX19.KY2fBvYyNCA0dYS7I6_rETGHT4YGkWZSh03XhXxwAvJ8XCfKlVJRY82U-0ERg01SFtPTZ-6BYu-sty1E67ioDA"
         }
      ), config_opts)
      @s.start_server(true)
    end

    after do
      @s.kill_server
    end

    def round_trip(nc)
      msgs = []
      nc.subscribe("hello") { |msg| msgs << msg.data }
      nc.publish("hello", "world")
      nc.flush
      wait_until(timeout: 2) { msgs == ["world"] }
    end

    it "should connect with user_credentials_data" do
      data = File.read(creds_file)
      reconnected = false
      nc = NATS::IO::Client.new
      nc.on_reconnect { reconnected = true }
      nc.connect("nats://127.0.0.1:4911", reconnect_time_wait: 0.1, user_credentials_data: data)
      round_trip(nc)

      # Signing again on a reconnect still works, and leaves the data alone.
      nc.force_reconnect
      wait_until(timeout: 5) { reconnected }
      nc.flush
      expect(data).to eql(File.read(creds_file))
      nc.close
    end

    it "should connect with user_jwt and user_seed" do
      lines = File.readlines(creds_file)
      jwt = lines[1].chomp
      seed = lines[lines.index { |l| l.include?("BEGIN USER NKEY SEED") } + 1].chomp.freeze

      nc = NATS.connect("nats://127.0.0.1:4911", reconnect: false, user_jwt: jwt, user_seed: seed)
      round_trip(nc)
      nc.close
    end

    it "should reject invalid in-memory credentials" do
      expect do
        NATS.connect("nats://127.0.0.1:4911", reconnect: false, user_credentials_data: "no credentials here")
      end.to raise_error(NATS::IO::Error, /No JWT found/)

      expect do
        NATS.connect("nats://127.0.0.1:4911", reconnect: false, user_jwt: "eyJ", user_seed: "SUAINVALID")
      end.to raise_error(ArgumentError, /invalid nkey seed/)

      expect do
        NATS.connect("nats://127.0.0.1:4911", user_jwt: "eyJ")
      end.to raise_error(ArgumentError, /user_jwt and user_seed must be given together/)
    end

    it "should reject conflicting credentials" do
      jwt_cb = -> { "jwt" }
      sig_cb = ->(nonce) { nonce }

      expect do
        NATS.connect("nats://127.0.0.1:4911", user_credentials: creds_file, user_credentials_data: File.read(creds_file))
      end.to raise_error(ArgumentError, /only one of user_credentials, user_credentials_data/)

      expect do
        NATS.connect("nats://127.0.0.1:4911", user_credentials: creds_file, nkeys_seed: "./spec/configs/nkeys/foo-user.nk")
      end.to raise_error(ArgumentError, /user callback and nkey defined/)

      expect do
        NATS.connect("nats://127.0.0.1:4911", user_jwt_cb: jwt_cb)
      end.to raise_error(ArgumentError, /user callback defined without a signature handler/)

      expect do
        NATS.connect("nats://127.0.0.1:4911", user_nkey_cb: -> { "UABC" })
      end.to raise_error(ArgumentError, /nkey defined without a signature handler/)

      expect do
        NATS.connect("nats://127.0.0.1:4911", user_jwt_cb: jwt_cb, user_signature_cb: sig_cb, user_nkey_cb: -> { "UABC" })
      end.to raise_error(ArgumentError, /user callback and nkey defined/)
    end
  end
end

# frozen_string_literal: true

describe "Client - no echo" do
  context "against a nats-server" do
    before(:all) do
      @s = NatsServerControl.new("nats://127.0.0.1:4850", "/tmp/test-nats.pid")
      @s.start_server(true)
    end

    after(:all) do
      @s.kill_server
    end

    it "should not receive its own messages when no_echo is set" do
      nc = NATS.connect(@s.uri, no_echo: true)
      nc2 = NATS.connect(@s.uri)

      own = []
      other = []
      nc.subscribe("no.echo") { |msg| own << msg.data }
      nc2.subscribe("no.echo") { |msg| other << msg.data }
      nc.flush
      nc2.flush

      nc.publish("no.echo", "from nc")
      nc.flush
      nc2.publish("no.echo", "from nc2")
      nc2.flush

      # nc2 got both messages; nc only the one of nc2.
      wait_until(timeout: 2) { other.size == 2 && own.size == 1 }
      sleep 0.2
      expect(other).to contain_exactly("from nc", "from nc2")
      expect(own).to eql(["from nc2"])

      nc.close
      nc2.close
    end

    it "should receive its own messages by default" do
      nc = NATS.connect(@s.uri)

      msgs = []
      nc.subscribe("echo") { |msg| msgs << msg.data }
      nc.publish("echo", "hi")
      nc.flush

      wait_until(timeout: 2) { msgs.size == 1 }
      expect(msgs).to eql(["hi"])

      nc.close
    end

    it "should send echo false in CONNECT only when no_echo is set" do
      nc = NATS::IO::Client.new
      nc.connect(@s.uri, no_echo: true)
      expect(JSON.parse(nc.send(:connect_command).split(" ", 2).last)["echo"]).to be(false)
      nc.close

      nc = NATS::IO::Client.new
      nc.connect(@s.uri)
      expect(JSON.parse(nc.send(:connect_command).split(" ", 2).last)).not_to have_key("echo")
      nc.close
    end
  end

  context "against a server without protocol 1" do
    before(:all) do
      @fake_nats_server = TCPServer.new 4851
      @fake_nats_server_th = Thread.new do
        loop do
          client = @fake_nats_server.accept
          client.write %(INFO {"version":"0.9.6","proto":0,"max_payload":1048576}\r\n)
          client.write "PONG\r\n"
        rescue IOError
          break if @fake_nats_server.closed?
        end
      end
    end

    after(:all) do
      @fake_nats_server_th.exit
      @fake_nats_server.close
    end

    it "should raise NoEchoNotSupported when no_echo is set" do
      errors = []
      nc = NATS::IO::Client.new
      nc.on_error { |e| errors << e }

      expect do
        nc.connect(servers: ["nats://127.0.0.1:4851"], reconnect: false, no_echo: true)
      end.to raise_error(NATS::IO::NoEchoNotSupported, /no echo option not supported/)
      expect(errors.first).to be_a(NATS::IO::NoEchoNotSupported)
    end

    it "should not retry a server that does not support no_echo" do
      nc = NATS::IO::Client.new
      started = NATS::MonotonicTime.now
      expect do
        nc.connect(servers: ["nats://127.0.0.1:4851"], no_echo: true, reconnect_time_wait: 0.1)
      end.to raise_error(NATS::IO::NoEchoNotSupported)
      # Dropped from the pool after the first attempt, instead of retrying it
      # max_reconnect_attempts times.
      expect(NATS::MonotonicTime.since(started)).to be < 1
    end

    it "should connect without no_echo" do
      nc = NATS::IO::Client.new
      expect do
        nc.connect(servers: ["nats://127.0.0.1:4851"], reconnect: false)
      end.not_to raise_error
      nc.close
    end
  end
end

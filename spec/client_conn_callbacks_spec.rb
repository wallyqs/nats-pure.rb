# frozen_string_literal: true

describe "Client - connection callbacks" do
  context "on_connect" do
    before do
      @s = NatsServerControl.new("nats://127.0.0.1:4930", "/tmp/test-nats.pid")
      @s.start_server(true)
    end

    after do
      @s.kill_server
    end

    it "should be called once connected, before connect returns" do
      events = []
      nc = NATS::IO::Client.new
      nc.on_connect { events << [:connect, nc.connected?] }
      nc.on_reconnect { events << :reconnect }
      nc.connect(@s.uri, reconnect_time_wait: 0.1)
      events << :returned
      expect(events).to eql([[:connect, true], :returned])

      # Reconnecting calls on_reconnect instead.
      nc.force_reconnect
      wait_until(timeout: 5) { events.include?(:reconnect) }
      expect(events.count { |e| e.is_a?(Array) }).to eql(1)
      nc.close
    end

    it "should be called once the first connect succeeds after retrying" do
      @s.kill_server
      connects = 0
      nc = NATS::IO::Client.new
      nc.on_connect { connects += 1 }
      t = Thread.new { nc.connect(@s.uri, reconnect_time_wait: 0.2, max_reconnect_attempts: -1) }
      sleep 0.5
      expect(connects).to eql(0)
      @s.start_server(true)
      t.join(5)
      expect(connects).to eql(1)
      nc.close
    end

    it "should hand errors of the callback to on_error" do
      errors = []
      nc = NATS::IO::Client.new
      nc.on_error { |e| errors << e }
      nc.on_connect { raise "boom" }
      expect { nc.connect(@s.uri) }.not_to raise_error
      expect(nc).to be_connected
      expect(errors.map(&:message)).to eql(["boom"])
      nc.close
    end
  end

  context "on_discovered_servers" do
    # Servers advertise their client URLs (connect_urls) only for addresses
    # other than loopback ones, unless told which address to advertise.
    before do
      @a = NatsServerControl.new("nats://127.0.0.1:4931", "/tmp/test-nats.pid", "-a 127.0.0.1 --cluster nats://127.0.0.1:4932 --cluster_name cb")
      @b = NatsServerControl.new("nats://127.0.0.1:4933", "/tmp/test-nats.pid", "-a 127.0.0.1 --cluster nats://127.0.0.1:4934 --cluster_name cb --routes nats://127.0.0.1:4932")
      @a.start_server(true)
    end

    after do
      @b.kill_server
      @a.kill_server
    end

    it "should be called when the server announces a new server" do
      discovered = []
      nc = NATS::IO::Client.new
      nc.on_discovered_servers { discovered << nc.discovered_servers.map { |s| s[:uri].port } }
      nc.connect(servers: [@a.uri.to_s], dont_randomize_servers: true)
      nc.flush
      expect(discovered).to be_empty

      @b.start_server(true)
      wait_until(timeout: 10) { discovered.any? }
      expect(discovered.first).to eql([4933])
      nc.close
    end

    it "should not be called when discovered servers are ignored" do
      discovered = 0
      nc = NATS::IO::Client.new
      nc.on_discovered_servers { discovered += 1 }
      nc.connect(servers: [@a.uri.to_s], ignore_discovered_urls: true)

      @b.start_server(true)
      # A second connection to B makes sure that the route is up.
      nc2 = NATS.connect(servers: [@b.uri.to_s], dont_randomize_servers: true)
      wait_until(timeout: 10) { nc2.discovered_servers.any? }
      sleep 0.2
      expect(discovered).to eql(0)
      nc2.close
      nc.close
    end
  end

  context "on_lame_duck_mode" do
    before do
      opts = {"pid_file" => "/tmp/test-nats-4935.pid", "host" => "127.0.0.1", "port" => 4935}
      @s = NatsServerControl.init_with_config_from_string(%(
        net: "127.0.0.1"
        port: 4935
        lame_duck_duration: "30s"
        lame_duck_grace_period: "10s"
      ), opts)
      @s.start_server(true)
    end

    after do
      @s.kill_server
    end

    it "should be called when the server enters lame duck mode" do
      ldm = 0
      nc = NATS::IO::Client.new
      nc.on_lame_duck_mode { ldm += 1 }
      nc.connect(@s.uri)
      nc.flush
      expect(ldm).to eql(0)

      Process.kill("USR2", @s.server_pid)
      wait_until(timeout: 10) { ldm == 1 }
      expect(nc.server_info[:ldm]).to be(true)
      nc.close
    end
  end
end

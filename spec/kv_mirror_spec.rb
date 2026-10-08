# frozen_string_literal: true

describe "KeyValue mirror and sources buckets" do
  describe "in one domain" do
    before do
      @tmpdir = Dir.mktmpdir("ruby-kv-mirror")
      @s = NatsServerControl.new("nats://127.0.0.1:4631", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
      @s.start_server(true)
    end

    after do
      @s.kill_server
      FileUtils.remove_entry(@tmpdir)
    end

    let(:nc) { NATS.connect(@s.uri) }
    let(:js) { nc.jetstream }

    after { nc.close }

    def key_value_of(kv, key)
      kv.get(key).value
    rescue NATS::KeyValue::KeyNotFoundError
      nil
    end

    it "creates a mirror of a bucket with direct gets, leaving the config unchanged" do
      # The server makes a mirror answer direct gets as its origin does.
      js.create_key_value(bucket: "TEST", direct: true)
      config = NATS::KeyValue::API::KeyValueConfig.new(bucket: "MIRROR", mirror: {name: "TEST"})
      js.create_key_value(config)
      expect(config.mirror).to eql({name: "TEST"})

      stream = js.stream_info("KV_MIRROR").config
      expect(stream.mirror[:name]).to eql("KV_TEST")
      expect(stream.mirror_direct).to be(true)
      expect(stream.allow_direct).to be(true)
      expect(stream.subjects).to be_nil
    end

    it "reads from the mirror and writes to the origin" do
      kv = js.create_key_value(bucket: "TEST", direct: true)
      kv.put("name", "derek")
      kv.put("age", "22")
      kv.put("v", "v")
      kv.delete("v")

      mkv = js.create_key_value(bucket: "MIRROR", mirror: {name: "KV_TEST"})
      wait_until(description: "the mirror to sync") { js.stream_info("KV_MIRROR").state.messages == 3 }

      expect(mkv.get("name").value).to eql("derek")
      expect(mkv.get("name").bucket).to eql("MIRROR")
      expect { mkv.get("v") }.to raise_error(NATS::KeyValue::KeyNotFoundError)
      expect(mkv.keys.to_a.sort).to eql(%w[age name])

      # Bound to by name, the mirror reads and writes the same way.
      mkv = js.key_value("MIRROR")
      mkv.put("name", "rip")
      mkv.put("v", "vv")
      expect(kv.get("v").value).to eql("vv")
      wait_until(description: "the update to reach the mirror") { key_value_of(mkv, "name") == "rip" }

      mkv.delete("v")
      expect { kv.get("v") }.to raise_error(NATS::KeyValue::KeyNotFoundError)
      wait_until(description: "the delete to reach the mirror") { key_value_of(mkv, "v").nil? }

      w = mkv.watchall
      expect(w.updates.key).to eql("age")
      w.stop
    end

    it "creates a bucket that takes the keys of other buckets" do
      kv_a = js.create_key_value(bucket: "A")
      kv_a.create("keyA", "1")
      kv_b = js.create_key_value(bucket: "B")
      kv_b.create("keyB", "1")

      kv_c = js.create_key_value(bucket: "C", sources: [{name: "A"}, {name: "KV_B"}])
      sources = js.stream_info("KV_C").config.sources.sort_by { |source| source[:name] }
      expect(sources.map { |source| source[:name] }).to eql(%w[KV_A KV_B])
      expect(sources.map { |source| source[:subject_transforms] }).to eql([
        [{src: "$KV.A.>", dest: "$KV.C.>"}],
        [{src: "$KV.B.>", dest: "$KV.C.>"}]
      ])
      expect(js.stream_info("KV_C").config.subjects).to eql(["$KV.C.>"])

      wait_until(description: "the sources to sync") { kv_c.status.values == 2 }
      expect(kv_c.get("keyA").value).to eql("1")
      expect(kv_c.get("keyB").value).to eql("1")

      # Writes to a bucket with sources go to that bucket.
      kv_c.put("keyC", "3")
      expect(kv_c.get("keyC").value).to eql("3")
      expect { kv_a.get("keyC") }.to raise_error(NATS::KeyValue::KeyNotFoundError)
    end

    it "takes a source with subject transforms of its own as it is" do
      js.add_stream(name: "EVENTS", subjects: ["events.>"])
      js.publish("events.one", "1")

      kv = js.create_key_value(bucket: "EV", sources: [
        {name: "EVENTS", subject_transforms: [{src: "events.>", dest: "$KV.EV.>"}]}
      ])
      source = js.stream_info("KV_EV").config.sources.first
      expect(source[:name]).to eql("EVENTS")
      expect(source[:subject_transforms]).to eql([{src: "events.>", dest: "$KV.EV.>"}])

      wait_until(description: "the source to sync") { kv.status.values == 1 }
      expect(kv.get("one").value).to eql("1")
    end

    it "raises ArgumentError for a source with both a domain and an external API" do
      expect do
        js.create_key_value(bucket: "MIRROR", mirror: {name: "TEST", domain: "HUB", external: {api: "$JS.HUB.API"}})
      end.to raise_error(ArgumentError, /domain and external are both set/)
    end
  end

  # Like TestKeyValueMirrorCrossDomains of nats.go.
  describe "across domains" do
    before do
      @hub_dir = Dir.mktmpdir("ruby-kv-mirror-hub")
      @leaf_dir = Dir.mktmpdir("ruby-kv-mirror-leaf")
      @hub = NatsServerControl.init_with_config_from_string(<<~CONF, {"host" => "127.0.0.1", "port" => 4632, "pid_file" => "/tmp/test-nats.pid"})
        host: 127.0.0.1
        port: 4632
        jetstream { domain: HUB, store_dir: "#{@hub_dir}" }
        leafnodes { host: 127.0.0.1, port: 7632 }
      CONF
      @leaf = NatsServerControl.init_with_config_from_string(<<~CONF, {"host" => "127.0.0.1", "port" => 4633, "pid_file" => "/tmp/test-nats.pid"})
        host: 127.0.0.1
        port: 4633
        jetstream { domain: LEAF, store_dir: "#{@leaf_dir}" }
        leafnodes { remotes = [ { url: "nats://127.0.0.1:7632" } ] }
      CONF
      @hub.start_server(true)
      @leaf.start_server(true)
    end

    after do
      @leaf.kill_server
      @hub.kill_server
      FileUtils.remove_entry(@hub_dir)
      FileUtils.remove_entry(@leaf_dir)
    end

    def key_value_of(kv, key)
      kv.get(key).value
    rescue NATS::KeyValue::KeyNotFoundError
      nil
    end

    it "mirrors a bucket of another domain, writing to it through the domain" do
      nc = NATS.connect(@hub.uri)
      lnc = NATS.connect(@leaf.uri)
      js = nc.jetstream
      ljs = lnc.jetstream

      kv = js.create_key_value(bucket: "TEST")
      kv.put("name", "derek")
      kv.put("age", "22")
      kv.put("v", "v")
      kv.delete("v")

      # Like nats.go, the domain becomes the external API prefix.
      ljs.create_key_value(bucket: "MIRROR", mirror: {name: "TEST", domain: "HUB"})
      mirror = ljs.stream_info("KV_MIRROR").config.mirror
      expect(mirror[:name]).to eql("KV_TEST")
      expect(mirror[:external][:api]).to eql("$JS.HUB.API")
      wait_until(description: "the mirror to sync") { ljs.stream_info("KV_MIRROR").state.messages == 3 }

      mkv = ljs.key_value("MIRROR")
      expect(mkv.get("name").value).to eql("derek")

      mkv.put("name", "rip")
      mkv.put("v", "vv")
      expect(kv.get("v").value).to eql("vv")
      mkv.delete("v")
      expect { kv.get("v") }.to raise_error(NATS::KeyValue::KeyNotFoundError)
      expect(kv.get("name").value).to eql("rip")

      kv.put("name", "ivan")
      wait_until(description: "the update to reach the mirror") { key_value_of(mkv, "name") == "ivan" }

      # The mirror still reads with the hub gone.
      nc.close
      @hub.kill_server
      expect(mkv.get("name").value).to eql("ivan")
      lnc.close
    end
  end
end

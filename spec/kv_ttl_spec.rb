# frozen_string_literal: true

describe "KeyValue TTLs and limit markers" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-kv-ttl")
    @s = NatsServerControl.new("nats://127.0.0.1:4624", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  describe "limit_marker_ttl" do
    it "enables per-message TTLs and subject delete markers on the bucket's stream" do
      kv = js.create_key_value(bucket: "MARKERS", limit_marker_ttl: 5)
      config = js.stream_info("KV_MARKERS").config
      expect(config.allow_msg_ttl).to eql(true)
      expect(config.subject_delete_marker_ttl).to eql(5 * 1_000_000_000)
      expect(kv.status.limit_marker_ttl).to eql(5)
    end

    it "is 0 for buckets without markers" do
      kv = js.create_key_value(bucket: "PLAIN")
      config = js.stream_info("KV_PLAIN").config
      expect(config.allow_msg_ttl).to be_falsey
      expect(config.subject_delete_marker_ttl).to be_falsey
      expect(kv.status.limit_marker_ttl).to eql(0)
    end

    it "is taken by update_key_value" do
      js.create_key_value(bucket: "LATER")
      kv = js.update_key_value(bucket: "LATER", limit_marker_ttl: 3)
      expect(kv.status.limit_marker_ttl).to eql(3)
    end
  end

  describe "create with ttl" do
    it "removes the key after its TTL, leaving a marker that get takes for a delete" do
      # With a history, the server raises TTLs to at least the
      # limit_marker_ttl, so that it does not miss markers.
      kv = js.create_key_value(bucket: "TTL", limit_marker_ttl: 60)
      rev = kv.create("short", "lived", ttl: 1)
      kv.put("long", "lived")
      expect(rev).to eql(1)

      msg = js.get_last_msg("KV_TTL", "$KV.TTL.short")
      expect(msg.headers[NATS::JetStream::Header::MSG_TTL]).to eql("1")

      eventually(timeout: 10) do
        expect { kv.get("short") }.to raise_error(NATS::KeyValue::KeyNotFoundError)
      end
      marker = js.get_last_msg("KV_TTL", "$KV.TTL.short")
      expect(marker.headers[NATS::KeyValue::MARKER_REASON]).to eql("MaxAge")
      expect(kv.get("long").value).to eql("lived")

      # Like a deleted key, the expired one can be created again.
      expect(kv.create("short", "again")).to be > rev
      expect(kv.get("short").value).to eql("again")
    end

    it "is refused by a bucket without limit markers" do
      kv = js.create_key_value(bucket: "NOTTL")
      expect do
        kv.create("k", "v", ttl: 5)
      end.to raise_error(NATS::JetStream::Error::APIError, /per-message TTL is disabled/)
    end

    it "refuses an invalid ttl before publishing" do
      kv = js.create_key_value(bucket: "TTL", limit_marker_ttl: 60)
      expect { kv.create("k", "v", ttl: 0.5) }.to raise_error(ArgumentError)
      expect { kv.get("k") }.to raise_error(NATS::KeyValue::KeyNotFoundError)
    end
  end

  describe "purge with ttl" do
    it "removes the purge marker after its TTL" do
      kv = js.create_key_value(bucket: "PTTL", history: 5, limit_marker_ttl: 1)
      kv.put("k", "1")
      kv.put("k", "2")
      kv.purge("k", ttl: 1)

      entries = kv.history("k").to_a
      expect(entries.map(&:operation)).to eql(["PURGE"])
      expect { kv.get("k") }.to raise_error(NATS::KeyValue::KeyNotFoundError)

      eventually(timeout: 10) do
        expect(js.stream_info("KV_PTTL").state.messages).to eql(0)
      end
    end

    it "purges without a ttl as before" do
      kv = js.create_key_value(bucket: "PNOTTL", history: 5)
      kv.put("k", "1")
      kv.purge("k")
      expect(js.stream_info("KV_PNOTTL").state.messages).to eql(1)
    end
  end

  it "refuses a TTL on delete" do
    kv = js.create_key_value(bucket: "DEL", limit_marker_ttl: 60)
    kv.put("k", "v")
    expect do
      kv.delete("k", ttl: 5)
    end.to raise_error(NATS::KeyValue::TTLOnDeleteNotSupportedError, "nats: TTL is not supported on delete")
    expect(kv.get("k").value).to eql("v")
  end

  describe "watch" do
    it "yields the markers of expired keys as purges" do
      kv = js.create_key_value(bucket: "WTTL", limit_marker_ttl: 60)
      w = kv.watchall
      expect(w.updates(timeout: 2)).to be_nil

      kv.create("k", "v", ttl: 1)
      entry = w.updates(timeout: 2)
      expect(entry.key).to eql("k")
      expect(entry.operation).to eql("PUT")

      marker = w.updates(timeout: 10)
      expect(marker.key).to eql("k")
      expect(marker.operation).to eql("PURGE")
      w.stop
    end

    it "leaves the markers of expired keys out of keys" do
      kv = js.create_key_value(bucket: "KTTL", limit_marker_ttl: 60)
      kv.create("gone", "v", ttl: 1)
      kv.put("kept", "v")
      eventually(timeout: 10) do
        expect { kv.get("gone") }.to raise_error(NATS::KeyValue::KeyNotFoundError)
      end
      expect(kv.keys.to_a).to eql(["kept"])
    end

    it "takes the markers of keys removed by the bucket's ttl for purges" do
      kv = js.create_key_value(bucket: "AGED", ttl: 1, limit_marker_ttl: 60)
      kv.put("k", "v")
      eventually(timeout: 10) do
        expect { kv.get("k") }.to raise_error(NATS::KeyValue::KeyNotFoundError)
      end
      entries = kv.history("k").to_a
      expect(entries.map(&:operation)).to eql(["PURGE"])
    end
  end
end

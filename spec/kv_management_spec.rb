# frozen_string_literal: true

describe "KeyValue bucket management" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-kv-management")
    @s = NatsServerControl.new("nats://127.0.0.1:4623", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  describe "update_key_value" do
    it "changes the configuration of a bucket" do
      kv = js.create_key_value(bucket: "UPD", history: 2)
      kv.put("a", "1")

      updated = js.update_key_value(bucket: "UPD", history: 5, ttl: 3600, description: "updated")
      expect(updated).to be_a NATS::KeyValue
      status = updated.status
      expect(status.history).to eql(5)
      expect(status.ttl).to eql(3600)
      expect(status.stream_info.config.description).to eql("updated")
      expect(updated.get("a").value).to eql("1")

      5.times { |i| updated.put("a", "v#{i}") }
      expect(updated.history("a").to_a.size).to eql(5)
    end

    it "takes a KeyValueConfig, which it leaves unchanged" do
      js.create_key_value(bucket: "UPD")
      config = NATS::KeyValue::API::KeyValueConfig.new(bucket: "UPD", ttl: 60)
      js.update_key_value(config)
      js.update_key_value(config)
      expect(config.ttl).to eql(60)
      expect(config.history).to be_nil
      expect(js.key_value("UPD").status.ttl).to eql(60)
    end

    it "raises BucketNotFoundError for a bucket that does not exist" do
      expect do
        js.update_key_value(bucket: "MISSING")
      end.to raise_error(NATS::KeyValue::BucketNotFoundError, /bucket not found/)
    end
  end

  describe "create_or_update_key_value" do
    it "creates a bucket that does not exist" do
      kv = js.create_or_update_key_value(bucket: "COU", history: 3)
      expect(kv.status.history).to eql(3)
      expect(kv.put("k", "v")).to eql(1)
    end

    it "updates a bucket that exists" do
      js.create_key_value(bucket: "COU", history: 3)
      kv = js.create_or_update_key_value(bucket: "COU", history: 7, max_bytes: 1024 * 1024)
      expect(kv.status.history).to eql(7)
      expect(kv.status.stream_info.config.max_bytes).to eql(1024 * 1024)
    end
  end

  describe "listing" do
    before do
      js.create_key_value(bucket: "ONE", history: 2)
      js.create_key_value(bucket: "TWO", history: 3)
      # Streams that are not buckets.
      js.add_stream(name: "ORDERS", subjects: ["orders.>"])
      js.add_stream(name: "KV_NOT_A_BUCKET", subjects: ["not.a.bucket"])
    end

    it "returns the names of the buckets" do
      expect(js.key_value_store_names).to match_array(["ONE", "TWO"])
    end

    it "returns the status of the buckets" do
      statuses = js.key_value_stores
      expect(statuses).to all(be_a(NATS::KeyValue::BucketStatus))
      expect(statuses.map { |status| [status.bucket, status.history] }).to match_array([["ONE", 2], ["TWO", 3]])
    end

    it "returns no buckets when there are none" do
      js.delete_key_value("ONE")
      js.delete_key_value("TWO")
      expect(js.key_value_store_names).to eql([])
      expect(js.key_value_stores).to eql([])
    end

    it "pages through many buckets" do
      buckets = (1..300).map { |i| format("B%03d", i) }
      buckets.each { |bucket| js.create_key_value(bucket: bucket, storage: "memory") }

      expect(js.key_value_store_names).to match_array(buckets + ["ONE", "TWO"])
      expect(js.key_value_stores.map(&:bucket)).to match_array(buckets + ["ONE", "TWO"])
    end
  end
end

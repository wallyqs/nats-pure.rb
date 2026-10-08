# frozen_string_literal: true

describe "KeyValue bucket and key errors" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-kv-errors")
    @s = NatsServerControl.new("nats://127.0.0.1:4634", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  describe "bucket names" do
    it "raises InvalidBucketNameError for names that are not of letters, digits, _ and -, like nats.go" do
      ["a.b", "a b", "a*", "a>", "a/b", "a!b", "a\nb", "ä"].each do |name|
        expect { js.create_key_value(bucket: name) }.to raise_error(NATS::KeyValue::InvalidBucketNameError, "nats: invalid bucket name")
        expect { js.update_key_value(bucket: name) }.to raise_error(NATS::KeyValue::InvalidBucketNameError)
        expect { js.create_or_update_key_value(bucket: name) }.to raise_error(NATS::KeyValue::InvalidBucketNameError)
        expect { js.key_value(name) }.to raise_error(NATS::KeyValue::InvalidBucketNameError)
        expect { js.delete_key_value(name) }.to raise_error(NATS::KeyValue::InvalidBucketNameError)
      end
      expect(js.stream_names).to eql([])

      expect(js.create_key_value(bucket: "Valid_name-1")).to be_a NATS::KeyValue
      expect(js.key_value("Valid_name-1")).to be_a NATS::KeyValue
    end

    it "raises BucketRequiredError, an InvalidBucketNameError, without a name" do
      [nil, ""].each do |name|
        expect { js.create_key_value(bucket: name) }.to raise_error(NATS::KeyValue::BucketRequiredError, "nats: bucket required")
        expect { js.key_value(name) }.to raise_error(NATS::KeyValue::InvalidBucketNameError)
        expect { js.delete_key_value(name) }.to raise_error(NATS::KeyValue::BucketRequiredError)
      end
      expect { js.create_key_value({}) }.to raise_error(NATS::KeyValue::BucketRequiredError)
    end

    it "keeps raising ArgumentError, as for the names that add_stream refuses" do
      expect(NATS::KeyValue::InvalidBucketNameError.ancestors).to include(ArgumentError)
      expect { js.create_key_value(bucket: "a.b") }.to raise_error(ArgumentError)
    end
  end

  it "raises KeyValueConfigRequiredError without a config" do
    expect { js.create_key_value(nil) }.to raise_error(NATS::KeyValue::KeyValueConfigRequiredError, "nats: config required")
    expect { js.update_key_value(nil) }.to raise_error(NATS::KeyValue::KeyValueConfigRequiredError)
    expect { js.create_or_update_key_value(nil) }.to raise_error(NATS::KeyValue::KeyValueConfigRequiredError)
    expect(NATS::KeyValue::KeyValueConfigRequiredError.ancestors).to include(ArgumentError)
  end

  describe "create_key_value of a bucket that exists" do
    it "returns the bucket when the config is the same" do
      js.create_key_value(bucket: "SAME", history: 2).put("k", "v")
      expect(js.create_key_value(bucket: "SAME", history: 2).get("k").value).to eql("v")
    end

    it "raises BucketExistsError, a StreamNameAlreadyInUse, when the config differs" do
      js.create_key_value(bucket: "TEST")
      expect do
        js.create_key_value(bucket: "TEST", history: 5)
      end.to raise_error(NATS::KeyValue::BucketExistsError) { |e|
        expect(e).to be_a NATS::JetStream::Error::StreamNameAlreadyInUse
        expect(e.message).to eql("nats: bucket name already in use: TEST")
        expect(e.bucket).to eql("TEST")
        expect(e.err_code).to eql(10058)
        expect(e.code).to eql(400)
      }
      expect(js.key_value("TEST").status.history).to eql(1)
    end
  end

  describe "create of a key that exists" do
    it "raises KeyExistsError, a KeyWrongLastSequenceError, like ErrKeyExists" do
      kv = js.create_key_value(bucket: "KEYS")
      expect(kv.create("name", "derek")).to eql(1)
      kv.put("name", "rip")
      expect do
        kv.create("name", "ivan")
      end.to raise_error(NATS::KeyValue::KeyExistsError, "nats: wrong last sequence: 2") { |e|
        expect(e).to be_a NATS::KeyValue::KeyWrongLastSequenceError
      }
      expect(kv.get("name").value).to eql("rip")
    end

    it "creates a deleted or purged key again" do
      kv = js.create_key_value(bucket: "KEYS", history: 5)
      kv.create("a", "1")
      kv.delete("a")
      expect(kv.create("a", "2")).to eql(3)
      kv.purge("a")
      expect(kv.create("a", "3")).to eql(5)
      expect(kv.get("a").value).to eql("3")
    end

    it "keeps raising a plain KeyWrongLastSequenceError on update" do
      kv = js.create_key_value(bucket: "KEYS")
      kv.put("a", "1")
      expect { kv.update("a", "2", last: 5) }.to raise_error(NATS::KeyValue::KeyWrongLastSequenceError) { |e|
        expect(e).not_to be_a NATS::KeyValue::KeyExistsError
      }
    end
  end
end

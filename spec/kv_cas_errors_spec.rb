# frozen_string_literal: true

describe "KeyValue revision conflicts" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-kv-cas")
    @s = NatsServerControl.new("nats://127.0.0.1:4628", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:kv) { js.create_key_value(bucket: "CAS") }

  after { nc.close }

  # Replicated streams report a wrong last sequence as 10164 instead of
  # 10071, which a standalone server cannot produce: make it answer so.
  def report_wrong_last_sequence_as(err_code)
    original = js.method(:publish)
    allow(js).to receive(:publish) do |subject, payload = "", **params|
      original.call(subject, payload, **params)
    rescue NATS::JetStream::Error::APIError => e
      raise e unless e.err_code == 10071

      raise NATS::JetStream::Error::BadRequest.new(code: 400, err_code: err_code, description: "wrong last sequence: #{e.description}")
    end
  end

  [10071, 10164].each do |err_code|
    context "with err_code #{err_code}" do
      before { report_wrong_last_sequence_as(err_code) }

      it "raises KeyWrongLastSequenceError on update" do
        kv.put("k", "1")
        expect { kv.update("k", "2", last: 5) }.to raise_error(NATS::KeyValue::KeyWrongLastSequenceError)
      end

      it "raises KeyWrongLastSequenceError on create of an existing key" do
        kv.put("k", "1")
        expect { kv.create("k", "2") }.to raise_error(NATS::KeyValue::KeyWrongLastSequenceError)
      end

      it "creates a deleted key again" do
        kv.put("k", "1")
        kv.delete("k")
        expect(kv.create("k", "2")).to eql(3)
        expect(kv.get("k").value).to eql("2")
      end
    end
  end
end

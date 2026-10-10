# frozen_string_literal: true

describe "KeyValue revision mismatches of delete and purge" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-kv-revision-mismatch")
    @s = NatsServerControl.new("nats://127.0.0.1:4629", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:kv) { js.create_key_value(bucket: "REV") }

  after { nc.close }

  it "raises KeyRevisionMismatchError, still a WrongLastSequence, from delete with a wrong last" do
    rev = kv.put("k", "1")
    expect { kv.delete("k", last: rev + 1) }.to raise_error(NATS::KeyValue::KeyRevisionMismatchError) { |e|
      expect(e).to be_a(NATS::JetStream::Error::WrongLastSequence)
      expect(e).to be_a(NATS::JetStream::Error::BadRequest)
      expect(e).to be_a(NATS::KeyValue::KeyRevisionMismatch)
      expect(e.err_code).to eql(10071)
      expect(e.code).to eql(400)
      expect(e.description).to eql("wrong last sequence: 1")
    }
    expect(kv.get("k").value).to eql("1")
  end

  it "raises KeyRevisionMismatchError from purge with a wrong last" do
    rev = kv.put("k", "1")
    expect { kv.purge("k", last: rev + 1) }.to raise_error(NATS::KeyValue::KeyRevisionMismatchError) { |e|
      expect(e).to be_a(NATS::JetStream::Error::WrongLastSequence)
      expect(e.err_code).to eql(10071)
    }
    expect(kv.get("k").value).to eql("1")
    expect(kv.purge("k", last: rev).seq).to eql(rev + 1)
  end

  it "catches the mismatches of update, delete and purge with KeyRevisionMismatch, like ErrKeyRevisionMismatch" do
    kv.put("k", "1")
    caught = [
      -> { kv.update("k", "2", last: 7) },
      -> { kv.delete("k", last: 7) },
      -> { kv.purge("k", last: 7) }
    ].map do |op|
      op.call
      nil
    rescue NATS::KeyValue::KeyRevisionMismatch => e
      e.class
    end
    expect(caught).to eql([
      NATS::KeyValue::KeyWrongLastSequenceError,
      NATS::KeyValue::KeyRevisionMismatchError,
      NATS::KeyValue::KeyRevisionMismatchError
    ])
  end

  it "raises it for err_code 10164 of replicated streams too" do
    original = js.method(:publish)
    allow(js).to receive(:publish) do |subject, payload = "", **params|
      original.call(subject, payload, **params)
    rescue NATS::JetStream::Error::APIError => e
      raise e unless e.err_code == 10071

      raise NATS::JetStream::Error::BadRequest.new(code: 400, err_code: 10164, description: "wrong last sequence: #{e.description}")
    end
    rev = kv.put("k", "1")

    expect { kv.delete("k", last: rev + 1) }.to raise_error(NATS::KeyValue::KeyRevisionMismatchError) { |e|
      expect(e.err_code).to eql(10164)
    }
    expect { kv.purge("k", last: rev + 1) }.to raise_error(NATS::KeyValue::KeyRevisionMismatchError)
  end

  it "leaves other errors as they are" do
    kv.put("k", "1")
    js.delete_key_value("REV")
    expect { kv.delete("k", last: 1) }.to raise_error(NATS::JetStream::Error::NoStreamResponse)
  end
end

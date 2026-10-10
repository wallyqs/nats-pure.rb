# frozen_string_literal: true

describe "JetStream fast-ingest batch publishing" do
  before(:all) do
    @tmpdir = Dir.mktmpdir("ruby-jetstream")
    @s = NatsServerControl.new("nats://127.0.0.1:4864", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:errors) { NATS::JetStream::Error }
  let(:reported) { Queue.new }
  let(:handler) { ->(e) { reported << e } }
  let(:reply_pattern) { /\A_INBOX\.(?<id>[A-Za-z0-9]+)\.(?<flow>\d+)\.(?<gap>ok|fail)\.(?<seq>\d+)\.(?<op>\d)\.\$FI\z/ }

  before do
    js.add_stream(name: "FAST", subjects: ["fast.>"], allow_batched: true)
  end

  after do
    js.delete_stream("FAST")
    nc.close
  end

  def messages
    js.stream_info("FAST").state.messages
  end

  def pop(queue, timeout = 2)
    Timeout.timeout(timeout) { queue.pop }
  end

  it "publishes messages and commits them with a last message" do
    fast = js.new_fast_publisher

    acks = 250.times.map { |i| fast.add("fast.a", i.to_s) }

    expect(acks.first).to eql(NATS::JetStream::FastPubAck.new(batch_seq: 1, ack_seq: 0))
    expect(acks.map(&:batch_seq)).to eql((1..250).to_a)
    expect(acks.map(&:ack_seq)).to all(be <= 250)

    ack = fast.commit("fast.b", "last", header: {"X-Last" => "1"})

    expect(ack).to be_a(NATS::JetStream::BatchAck)
    expect(ack).to have_attributes(stream: "FAST", seq: 251, batch: fast.id, count: 251)
    expect(fast.closed?).to be(true)
    expect(messages).to eql(251)
    expect(js.get_msg("FAST", seq: 251).headers).to include("X-Last" => "1")
    expect { fast.add("fast.a") }.to raise_error(errors::BatchClosed)
    expect { fast.commit("fast.a") }.to raise_error(errors::BatchClosed)
  end

  it "ends the batch with an end-of-batch marker that is not stored" do
    fast = js.new_fast_publisher
    10.times { |i| fast.add("fast.a", i.to_s) }

    ack = fast.close

    expect(ack).to have_attributes(stream: "FAST", seq: 10, count: 10, batch: fast.id)
    expect(messages).to eql(10)
    expect { fast.close }.to raise_error(errors::BatchClosed)
  end

  it "refuses to close an empty batch" do
    expect { js.new_fast_publisher.close }.to raise_error(errors::EmptyBatch)
  end

  it "uses the reply subjects of orbit.go" do
    seen = nc.subscribe("fast.>")
    fast = js.new_fast_publisher(flow: 7, continue_on_gap: true)
    3.times { fast.add_msg(NATS::Msg.new(subject: "fast.a", data: "x")) }
    fast.commit("fast.a", "x")

    replies = 4.times.map { seen.next_msg(timeout: 1).reply.match(reply_pattern) }
    expect(replies).to all(be_truthy)
    expect(replies.map { |m| m[:id] }.uniq).to eql([fast.id])
    expect(replies.map { |m| [m[:flow], m[:gap], m[:seq], m[:op]] }).to eql([
      %w[7 ok 1 0], %w[7 ok 2 1], %w[7 ok 3 1], %w[7 ok 4 2]
    ])

    js.new_fast_publisher.tap { |f| f.add("fast.b") }.close
    first = seen.next_msg(timeout: 1).reply.match(reply_pattern)
    expect([first[:flow], first[:gap], first[:op]]).to eql(%w[100 fail 0])
    eob = seen.next_msg(timeout: 1).reply.match(reply_pattern)
    expect([eob[:seq], eob[:op]]).to eql(%w[2 3])
  end

  it "waits for acks when too many are outstanding" do
    fast = js.new_fast_publisher(flow: 1, max_outstanding_acks: 1)

    acks = 20.times.map { fast.add("fast.a", "x") }

    expect(acks.drop(1)).to all(satisfy { |a| a.ack_seq >= a.batch_seq })
    expect(fast.close.count).to eql(20)
  end

  it "does not change the messages it is given" do
    fast = js.new_fast_publisher
    msg = NATS::Msg.new(subject: "fast.a", data: "x", header: {"X-A" => "a"})

    fast.add_msg(msg, msg_id: "m1")
    fast.close

    expect(msg.header).to eql("X-A" => "a")
    expect(msg.reply).to be_nil
    expect(js.get_msg("FAST", seq: 1).headers).to include("X-A" => "a", NATS::JetStream::Header::MSG_ID => "m1")
  end

  it "raises FastBatchNotEnabled at once for a stream without allow_batched" do
    js.add_stream(name: "PLAIN", subjects: ["plain"])
    fast = js.new_fast_publisher(ack_timeout: 5)

    started = NATS::MonotonicTime.now
    expect { fast.add("plain", "x") }.to raise_error(errors::FastBatchNotEnabled) do |e|
      expect(e).to be_a(errors::BadRequest)
      expect(e).to have_attributes(code: 400, err_code: 10205)
    end
    expect(NATS::MonotonicTime.now - started).to be < 2
    expect(fast.closed?).to be(true)
  ensure
    js.delete_stream("PLAIN")
  end

  it "reports a gap and ends the batch" do
    fast = js.new_fast_publisher(error_handler: handler)
    fast.add("fast.a", "1")
    # Loses message 2.
    fast.instance_variable_set(:@sequence, 2)
    fast.add("fast.a", "3")

    gap = pop(reported)
    expect(gap).to be_a(errors::FastBatchGapDetected)
    expect(gap).to have_attributes(expected_last_seq: 2, current_seq: 3)
    expect(gap.message).to eql("nats: fast batch gap detected: expected last sequence 2; current sequence 3")

    eventually { expect(fast.closed?).to be(true) }
    expect { fast.add("fast.a", "4") }.to raise_error(errors::BatchClosed)
    expect(messages).to eql(1)
  end

  it "reports a gap and goes on with continue_on_gap" do
    fast = js.new_fast_publisher(continue_on_gap: true, error_handler: handler)
    fast.add("fast.a", "1")
    fast.instance_variable_set(:@sequence, 2)
    fast.add("fast.a", "3")

    expect(pop(reported)).to have_attributes(expected_last_seq: 2, current_seq: 3)
    ack = fast.commit("fast.a", "4")

    expect(ack).to have_attributes(count: 4, seq: 3)
    expect(messages).to eql(3)
  end

  it "reports a message that the stream refuses" do
    fast = js.new_fast_publisher(continue_on_gap: true, error_handler: handler)
    fast.add("fast.a", "1")
    fast.add("fast.a", "2", expected_last_seq: 99)

    error = pop(reported)
    expect(error).to be_a(errors::BadRequest)
    expect(error).to have_attributes(err_code: 10071, seq: 2)

    expect(fast.commit("fast.a", "3").count).to eql(3)
    expect(messages).to eql(2)
  end

  it "raises ArgumentError for invalid options" do
    expect { js.new_fast_publisher(flow: 0) }.to raise_error(ArgumentError)
    expect { js.new_fast_publisher(flow: 65_536) }.to raise_error(ArgumentError)
    expect { js.new_fast_publisher(max_outstanding_acks: 0) }.to raise_error(ArgumentError)
    expect { js.new_fast_publisher(ack_timeout: -1) }.to raise_error(ArgumentError)
    expect { js.new_fast_publisher(continue_on_gap: nil) }.to raise_error(ArgumentError)
    expect { js.new_fast_publisher(error_handler: 1) }.to raise_error(ArgumentError)
    expect { js.new_fast_publisher(bogus: 1) }.to raise_error(ArgumentError)
    expect { js.new_fast_publisher.add("fast.a", ttl: 0) }.to raise_error(ArgumentError)
  end

  it "maps the fast batch error codes of nats-server" do
    from_error = ->(err) { NATS::JetStream.const_get(:JS).from_error(err) }

    expect(from_error.call(code: 400, err_code: 10206)).to be_a(errors::FastBatchInvalidPattern)
    expect(from_error.call(code: 400, err_code: 10207)).to be_a(errors::FastBatchInvalidID)
    expect(from_error.call(code: 400, err_code: 10208)).to be_a(errors::FastBatchUnknownID)
    expect(from_error.call(code: 400, err_code: 10209)).to be_a(errors::MirrorWithBatchPublish)
    expect(from_error.call(code: 429, err_code: 10211)).to be_a(errors::BatchPublishTooManyInflight)
    expect(from_error.call(code: 400, err_code: 10204)).to be_a(errors::ConsumerInvalidReset)
  end

  it "raises FastBatchUnknownID for a message of a batch the server does not know" do
    inbox = nc.new_inbox
    sub = nc.subscribe("#{inbox}.>")
    nc.publish("fast.a", "x", "#{inbox}.100.fail.2.1.$FI")

    reply = JSON.parse(sub.next_msg(timeout: 1).data, symbolize_names: true)
    error = NATS::JetStream.const_get(:JS).from_error(reply[:error])
    expect(error).to be_a(errors::FastBatchUnknownID).and have_attributes(err_code: 10208)
  end

  context "with a server that allows one batch in flight per stream" do
    before(:all) do
      @limited_dir = Dir.mktmpdir("ruby-jetstream")
      conf = File.join(@limited_dir, "js.conf")
      File.write(conf, <<~CONF)
        jetstream {
          store_dir: "#{@limited_dir}"
          limits { batch { max_inflight_per_stream: 1 } }
        }
      CONF
      @limited = NatsServerControl.new("nats://127.0.0.1:4865", "/tmp/test-nats-limited.pid", "-c #{conf}")
      @limited.start_server(true)
    end

    after(:all) do
      @limited.kill_server
      FileUtils.remove_entry(@limited_dir)
    end

    it "raises BatchPublishTooManyInflight, with status code 429" do
      lnc = NATS.connect(@limited.uri)
      ljs = lnc.jetstream
      ljs.add_stream(name: "FAST", subjects: ["fast.>"], allow_batched: true)

      first = ljs.new_fast_publisher
      first.add("fast.a", "one")

      expect { ljs.new_fast_publisher.add("fast.b", "two") }.to raise_error(errors::BatchPublishTooManyInflight) do |e|
        expect(e).to have_attributes(code: 429, err_code: 10211)
      end
      expect(first.close.count).to eql(1)
    ensure
      lnc&.close
    end
  end
end

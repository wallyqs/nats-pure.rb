# frozen_string_literal: true

describe "JetStream push subscription consumer sequence mismatch" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-push-seq")
    @s = NatsServerControl.new("nats://127.0.0.1:4765", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:errors) { Queue.new }
  let(:nc) do
    NATS.connect(@s.uri).tap { |nc| nc.on_error { |e| errors << e } }
  end
  let(:js) { nc.jetstream }

  after { nc.close }

  before { js.add_stream(name: "SEQ", subjects: ["seq.>"]) }

  def mismatch_errors(wait)
    deadline = Time.now + wait
    found = []
    while (left = deadline - Time.now) > 0
      err = errors.pop(timeout: left)
      break unless err

      found << err if err.is_a?(NATS::JetStream::Error::ConsumerSequenceMismatch)
      break unless found.empty?
    end
    found
  end

  it "reports the messages the subscription missed, from where it could resume" do
    sub = js.subscribe("seq.a", idle_heartbeat: 0.2)
    # Drop the messages beyond the first two, as for a slow consumer.
    sub.pending_msgs_limit = 2
    5.times { |i| js.publish("seq.a", i.to_s) }
    nc.flush

    eventually { expect(sub.dropped).to eql(3) }
    expect(Array.new(2) { sub.next_msg(timeout: 1).data }).to eql(%w[0 1])

    err = mismatch_errors(3).first
    expect(err).to be_a(NATS::JetStream::Error::ConsumerSequenceMismatch)
    expect(err).to be_a(NATS::JetStream::Error)
    expect(err.consumer_sequence).to eql(2)
    expect(err.last_consumer_sequence).to eql(5)
    expect(err.stream_resume_sequence).to eql(2)
    expect(err.message).to eql(
      "nats: sequence mismatch for consumer at sequence 2 (3 sequences behind), " \
      "should restart consumer from stream sequence 2"
    )
    sub.unsubscribe
  end

  it "reports nothing while the subscription got every message" do
    got = Queue.new
    sub = js.subscribe("seq.a", idle_heartbeat: 0.2) { |msg| got << msg }
    5.times { |i| js.publish("seq.a", i.to_s) }

    expect(Array.new(5) { got.pop(timeout: 2)&.data }).to eql(%w[0 1 2 3 4])
    expect(mismatch_errors(1)).to be_empty
    sub.unsubscribe
  end

  it "reports nothing before a message came" do
    sub = js.subscribe("seq.a", idle_heartbeat: 0.2)

    expect(mismatch_errors(1)).to be_empty
    expect { sub.next_msg(timeout: 0.1) }.to raise_error(NATS::Timeout)
    sub.unsubscribe
  end
end

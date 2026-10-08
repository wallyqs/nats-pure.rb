# frozen_string_literal: true

describe "JetStream publish_async_ack_handler" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-publish-async-ack-handler")
    @s = NatsServerControl.new("nats://127.0.0.1:4739", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }

  before { nc.jsm.add_stream(name: "ACKS", subjects: ["acks.>"]) }

  after { nc.close }

  it "is called with the message and the ack of each acked publish" do
    acks = Queue.new
    js = nc.jetstream(publish_async_ack_handler: ->(msg, ack) { acks << [msg, ack] })
    futures = 5.times.map { |i| js.publish_async("acks.a", "msg-#{i}") }
    futures << js.publish_msg_async(NATS::Msg.new(subject: "acks.b", data: "last"))
    js.publish_async_complete(timeout: 5)

    got = 6.times.map { acks.pop(timeout: 5) }
    expect(got.map(&:first)).to match_array(futures.map(&:msg))
    got.each do |msg, ack|
      expect(ack).to be_a(NATS::JetStream::PubAck)
      expect(ack).to equal(futures.find { |future| future.msg.equal?(msg) }.ack)
    end
    expect(got.map { |_, ack| ack.seq }.sort).to eql((1..6).to_a)
  end

  it "is called once the future has the ack, like nats.go" do
    published = Queue.new
    done = Queue.new
    js = nc.jetstream(publish_async_ack_handler: ->(_msg, _ack) { done << published.pop(timeout: 5)&.done? })
    published << js.publish_async("acks.a", "hi")
    expect(done.pop(timeout: 5)).to eql(true)
  end

  it "is not called for a publish that fails, which goes to the error handler" do
    acks = Queue.new
    errors = Queue.new
    js = nc.jetstream(
      publish_async_ack_handler: ->(msg, ack) { acks << [msg, ack] },
      publish_async_err_handler: ->(msg, err) { errors << [msg, err] }
    )
    future = js.publish_async("acks.a", "hi", stream: "OTHER")
    expect { future.wait(5) }.to raise_error(NATS::JetStream::Error::BadRequest)
    msg, err = errors.pop(timeout: 5)
    expect(msg).to equal(future.msg)
    expect(err).to be_a(NATS::JetStream::Error::BadRequest)

    js.publish_async("acks.a", "ok").wait(5)
    expect(acks.pop(timeout: 5)[1].seq).to eql(1)
    expect(acks).to be_empty
  end

  it "is not called by the synchronous publishes" do
    acks = Queue.new
    js = nc.jetstream(publish_async_ack_handler: ->(msg, ack) { acks << ack })
    js.publish("acks.a", "hi")
    js.publish_msg(NATS::Msg.new(subject: "acks.a", data: "hi"))
    js.publish_async("acks.a", "hi").wait(5)
    expect(acks.pop(timeout: 5).seq).to eql(3)
    expect(acks).to be_empty
  end

  it "reports what it raises to the error callback of the connection" do
    errors = Queue.new
    nc.on_error { |e| errors << e }
    js = nc.jetstream(publish_async_ack_handler: ->(_msg, _ack) { raise "boom" })
    future = js.publish_async("acks.a", "hi")
    expect(future.wait(5).seq).to eql(1)
    expect(errors.pop(timeout: 5).message).to eql("boom")
    expect(js.publish_async("acks.a", "again").wait(5).seq).to eql(2)
  end

  it "must be callable" do
    expect do
      nc.jetstream(publish_async_ack_handler: "nope")
    end.to raise_error(ArgumentError, /publish_async_ack_handler/)
  end
end

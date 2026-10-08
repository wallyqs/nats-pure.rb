# frozen_string_literal: true

require "tmpdir"

describe "JetStream cleanup_publisher" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-cleanup-publisher")
    @s = NatsServerControl.new("nats://127.0.0.1:4877", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:failed) { Queue.new }
  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream(publish_async_err_handler: ->(msg, err) { failed << [msg.subject, err] }) }

  after { nc.close }

  # The subscription of the context to the replies of publish_async.
  def reply_sub
    js.instance_variable_get(:@async_sub)
  end

  def subscribed?(sub)
    nc.instance_variable_get(:@subs).value?(sub)
  end

  it "fails the futures that await acks and unsubscribes from the replies" do
    # A subscriber that takes the messages without acking them.
    nc.subscribe("silent") {}
    nc.flush

    futures = Array.new(3) { js.publish_async("silent", "hi") }
    nc.flush
    expect(js.publish_async_pending).to eql(3)
    sub = reply_sub
    expect(subscribed?(sub)).to be(true)

    expect(js.cleanup_publisher).to be_nil
    expect(futures.map(&:done?)).to eql([true, true, true])
    expect(futures.map(&:err)).to all(be_a(NATS::JetStream::Error::PublisherClosed))
    expect(futures.first.err.message).to eql("nats: jetstream context closed")
    expect { futures.first.wait(1) }.to raise_error(NATS::JetStream::Error::PublisherClosed)
    expect(js.publish_async_pending).to eql(0)
    js.publish_async_complete(timeout: 1)
    expect(Array.new(3) { failed.pop(timeout: 1) }.map(&:first)).to eql(%w[silent silent silent])
    expect(subscribed?(sub)).to be(false)
  end

  it "publishes again afterwards, with a new reply subscription" do
    js.add_stream(name: "CLEAN", subjects: ["clean.>"])
    first = js.publish_async("clean.a", "1")
    expect(first.wait(2).seq).to eql(1)
    old = reply_sub
    js.cleanup_publisher

    future = js.publish_async("clean.a", "2")
    expect(future.wait(2).seq).to eql(2)
    expect(subscribed?(old)).to be(false)
    expect(subscribed?(reply_sub)).to be(true)
    expect(reply_sub).not_to equal(old)
    expect(failed).to be_empty
  end

  it "does nothing without async publishes, and after the connection closed" do
    expect(js.cleanup_publisher).to be_nil

    js.add_stream(name: "CLEAN", subjects: ["clean.>"])
    js.publish_async("clean.a", "1").wait(2)
    nc.close
    expect(js.cleanup_publisher).to be_nil
    expect(failed).to be_empty
  end

  it "no longer fails the futures of a later close once cleaned up" do
    js.add_stream(name: "CLEAN", subjects: ["clean.>"])
    js.publish_async("clean.a", "1").wait(2)
    js.cleanup_publisher
    listeners = nc.instance_variable_get(:@status_listeners)
    expect(listeners).to be_empty
  end
end

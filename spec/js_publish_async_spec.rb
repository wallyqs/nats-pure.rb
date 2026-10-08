# frozen_string_literal: true

describe "JetStream async publish" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-publish-async")
    @s = NatsServerControl.new("nats://127.0.0.1:4736", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  def elapsed
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    yield
    Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
  end

  # A subscriber that takes the messages on a subject without acking them,
  # so that their publishes await acks.
  def silent_subscriber(subject)
    nc.subscribe(subject) {}
    nc.flush
  end

  describe "with a stream" do
    before do
      nc.jsm.add_stream(name: "ASYNC", subjects: ["async.>"])
    end

    it "publishes without waiting and acks each message" do
      futures = 100.times.map { |i| js.publish_async("async.a", "msg-#{i}") }
      expect(futures).to all(be_a(NATS::JetStream::PubAckFuture))
      expect(js.publish_async_complete(timeout: 5)).to eql(true)
      expect(js.publish_async_pending).to eql(0)

      expect(futures).to all(be_done)
      expect(futures.map(&:err)).to all(be_nil)
      expect(futures.map { |future| future.ack.seq }).to eql((1..100).to_a)
      expect(futures.map { |future| future.ack.stream }.uniq).to eql(["ASYNC"])
      expect(futures.first.wait).to eql(futures.first.ack)
      expect(futures.last.msg.data).to eql("msg-99")
      expect(nc.jsm.stream_info("ASYNC").state.messages).to eql(100)
    end

    it "gets the acks on a single subscription, with a token per message" do
      replies = 3.times.map { js.publish_async("async.a", "hi").msg.reply }
      js.publish_async_complete(timeout: 5)

      prefixes = replies.map { |reply| reply[0...reply.rindex(".")] }
      expect(prefixes.uniq.size).to eql(1)
      expect(prefixes.first).to start_with("_INBOX.")
      expect(replies.uniq.size).to eql(3)
      expect(nc.instance_variable_get(:@subs).values.count { |sub| sub.subject == "#{prefixes.first}.*" }).to eql(1)
    end

    it "takes the options of publish" do
      future = js.publish_async("async.h", "hi", header: {"foo" => "bar"}, stream: "ASYNC")
      ack = future.wait(5)
      expect(ack.seq).to eql(1)
      expect(nc.jsm.get_msg("ASYNC", seq: 1).headers["foo"]).to eql("bar")
    end

    it "fails the future with the error of the stream, and calls the error handler" do
      errors = Queue.new
      js = nc.jetstream(publish_async_err_handler: ->(msg, err) { errors << [msg, err] })
      future = js.publish_async("async.a", "hi", stream: "OTHER")

      expect { future.wait(5) }.to raise_error(NATS::JetStream::Error::BadRequest)
      expect(future.err).to be_a(NATS::JetStream::Error::BadRequest)
      expect(future.ack).to be_nil
      msg, err = errors.pop
      expect(msg).to equal(future.msg)
      expect(err).to equal(future.err)
      expect(js.publish_async_pending).to eql(0)
    end
  end

  describe "without a stream" do
    it "fails with NoStreamResponse after the retries" do
      errors = Queue.new
      js = nc.jetstream(publish_async_err_handler: ->(msg, err) { errors << err })

      future = nil
      took = elapsed do
        future = js.publish_async("nostream", "hi")
        expect { future.wait(5) }.to raise_error(NATS::JetStream::Error::NoStreamResponse)
      end
      expect(took).to be_between(0.5, 1.5)
      expect(errors.pop).to equal(future.err)

      took = elapsed do
        future = js.publish_async("nostream", "hi", retry_attempts: 0)
        expect { future.wait(5) }.to raise_error(NATS::JetStream::Error::NoStreamResponse)
      end
      expect(took).to be < 0.25
      expect(js.publish_async_pending).to eql(0)
    end

    it "publishes to a stream that comes up while it retries" do
      future = js.publish_async("late", "hi", retry_attempts: 20, retry_wait: 0.1)
      sleep 0.3
      expect(future).not_to be_done
      nc.jsm.add_stream(name: "LATE", subjects: ["late"])
      expect(future.wait(5).stream).to eql("LATE")
    end
  end

  describe "while acks are pending" do
    it "stalls once more messages await acks than may" do
      silent_subscriber("silent")
      js = nc.jetstream(publish_async_max_pending: 2, publish_async_stall_wait: 0.3)
      2.times { js.publish_async("silent", "hi") }
      expect(js.publish_async_pending).to eql(2)

      took = elapsed do
        expect { js.publish_async("silent", "hi") }.to raise_error(NATS::JetStream::Error::TooManyStalledMsgs)
      end
      expect(took).to be_between(0.3, 1.0)
      expect(js.publish_async_pending).to eql(2)

      took = elapsed do
        expect { js.publish_async("silent", "hi", stall_wait: 0.1) }.to raise_error(NATS::JetStream::Error::TooManyStalledMsgs)
      end
      expect(took).to be < 0.3
    end

    it "goes on once a message is acked" do
      nc.subscribe("slow") do |msg|
        sleep 0.2
        msg.respond({stream: "FAKE", seq: 1}.to_json)
      end
      nc.flush
      js = nc.jetstream(publish_async_max_pending: 1, publish_async_stall_wait: 5)
      first = js.publish_async("slow", "hi")
      second = nil
      took = elapsed { second = js.publish_async("slow", "hi") }
      expect(took).to be_between(0.1, 1.0)
      expect(first).to be_done
      expect(second.wait(5).stream).to eql("FAKE")
    end

    it "fails the futures past their timeout" do
      silent_subscriber("silent")
      errors = Queue.new
      js = nc.jetstream(publish_async_timeout: 0.3, publish_async_err_handler: ->(_msg, err) { errors << err })
      future = js.publish_async("silent", "hi")
      other = js.publish_async("silent", "hi", timeout: 5)

      took = elapsed do
        expect { future.wait(5) }.to raise_error(NATS::JetStream::Error::AsyncPublishTimeout)
      end
      expect(took).to be_between(0.2, 1.0)
      expect(errors.pop).to equal(future.err)
      expect(other).not_to be_done
      expect(js.publish_async_pending).to eql(1)
    end

    it "times out waiting for acks" do
      silent_subscriber("silent")
      future = js.publish_async("silent", "hi")
      expect { future.wait(0.1) }.to raise_error(NATS::Timeout)
      expect { js.publish_async_complete(timeout: 0.1) }.to raise_error(NATS::Timeout)
      expect(js.publish_async_pending).to eql(1)
    end
  end

  it "refuses invalid options" do
    expect { nc.jetstream(publish_async_max_pending: 0) }.to raise_error(ArgumentError)
    expect { nc.jetstream(publish_async_err_handler: "handler") }.to raise_error(ArgumentError)
    expect { js.publish_async("s", "hi", timeout: -1) }.to raise_error(ArgumentError)
    expect { js.publish_async("s", "hi", stall_wait: 0) }.to raise_error(ArgumentError)
    expect { js.publish_async("s", "hi", retry_attempts: "1") }.to raise_error(ArgumentError)
    expect(js.publish_async_pending).to eql(0)
  end
end

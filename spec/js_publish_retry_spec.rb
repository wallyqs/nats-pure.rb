# frozen_string_literal: true

describe "JetStream publish retry" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-publish-retry")
    @s = NatsServerControl.new("nats://127.0.0.1:4735", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  # The seconds that the block took to raise NoStreamResponse, and the
  # requests it sent.
  def no_stream_response
    requests = 0
    allow(nc).to receive(:request_msg).and_wrap_original do |original, *args, **opts|
      requests += 1
      original.call(*args, **opts)
    end
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    expect { yield }.to raise_error(NATS::JetStream::Error::NoStreamResponse)
    [Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, requests]
  end

  it "retries twice, 250ms apart, as nats.go does" do
    elapsed, requests = no_stream_response { js.publish("nostream", "hi") }
    expect(requests).to eql(3)
    expect(elapsed).to be_between(0.5, 1.5)
  end

  it "takes retry_attempts and retry_wait" do
    elapsed, requests = no_stream_response { js.publish("nostream", "hi", retry_attempts: 0) }
    expect(requests).to eql(1)
    expect(elapsed).to be < 0.25

    elapsed, requests = no_stream_response { js.publish("nostream", "hi", retry_attempts: 4, retry_wait: 0.1) }
    expect(requests).to eql(5)
    expect(elapsed).to be_between(0.4, 1.4)
  end

  it "takes the defaults of the context" do
    js = nc.jetstream(retry_attempts: 1, retry_wait: 0.3)
    elapsed, requests = no_stream_response { js.publish("nostream", "hi") }
    expect(requests).to eql(2)
    expect(elapsed).to be_between(0.3, 1.3)

    elapsed, requests = no_stream_response { js.publish("nostream", "hi", retry_attempts: 0) }
    expect(requests).to eql(1)
    expect(elapsed).to be < 0.25
  end

  it "retries within the timeout" do
    elapsed, requests = no_stream_response do
      js.publish("nostream", "hi", retry_attempts: -1, retry_wait: 0.1, timeout: 0.55)
    end
    expect(requests).to be_between(4, 6)
    expect(elapsed).to be_between(0.4, 1.0)

    # No retry when its wait would not end before the timeout.
    elapsed, requests = no_stream_response { js.publish("nostream", "hi", timeout: 0.2) }
    expect(requests).to eql(1)
    expect(elapsed).to be < 0.2
  end

  it "publishes to a stream that comes up while it retries" do
    creator = Thread.new do
      sleep 0.3
      nc.jsm.add_stream(name: "LATE", subjects: ["late"])
    end
    ack = js.publish("late", "hi", retry_attempts: 10, retry_wait: 0.1)
    creator.join
    expect(ack.stream).to eql("LATE")
    expect(ack.seq).to eql(1)
  end

  it "raises the errors of streams without retrying" do
    nc.jsm.add_stream(name: "S", subjects: ["s"])
    allow(nc).to receive(:request_msg).and_call_original
    expect do
      js.publish("s", "hi", stream: "OTHER")
    end.to raise_error(NATS::JetStream::Error::BadRequest)
    expect(nc).to have_received(:request_msg).once
  end

  it "refuses invalid retry options" do
    expect { js.publish("s", "hi", retry_attempts: 1.5) }.to raise_error(ArgumentError)
    expect { js.publish("s", "hi", retry_wait: -1) }.to raise_error(ArgumentError)
    expect { js.publish("s", "hi", retry_wait: "1") }.to raise_error(ArgumentError)
    expect { nc.jetstream(retry_attempts: nil).publish("s", "hi") }.to raise_error(ArgumentError)
  end
end

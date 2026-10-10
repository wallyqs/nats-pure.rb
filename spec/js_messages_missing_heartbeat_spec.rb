# frozen_string_literal: true

describe "JetStream messages with err_on_missing_heartbeat" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-messages-hb")
    @s = NatsServerControl.new("nats://127.0.0.1:4767", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri, max_reconnect_attempts: -1, reconnect_time_wait: 0.2) }
  let(:js) { nc.jetstream }
  let(:psub) { js.pull_subscribe("hb.>", "c1", stream: "HB") }
  let(:pulls) { nc.subscribe("$JS.API.CONSUMER.MSG.NEXT.HB.c1") }

  before do
    js.add_stream(name: "HB", subjects: ["hb.>"])
    js.add_consumer("HB", durable_name: "c1", ack_policy: "explicit")
    psub
    pulls
    nc.flush
  end

  after { nc.close }

  def pulls_sent
    nc.flush
    Array.new(pulls.pending_queue.size) { pulls.next_msg }
  end

  # Stops the server, which keeps the connection but sends nothing more,
  # until the block returns.
  def server_stopped
    pid = @s.server_pid
    Process.kill("STOP", pid)
    yield
  ensure
    Process.kill("CONT", pid)
  end

  it "raises NoHeartbeat by default, like nats.go" do
    msgs = psub.messages(expires: 2, heartbeat: 0.5)
    expect(msgs.opts[:err_on_missing_heartbeat]).to be(true)
    expect { msgs.next(timeout: 0.5) }.to raise_error(NATS::Timeout)

    server_stopped do
      expect { msgs.next(timeout: 3) }.to raise_error(NATS::JetStream::Error::NoHeartbeat)
    end
    msgs.stop
  end

  it "pulls again without raising when false" do
    msgs = psub.messages(expires: 2, heartbeat: 0.5, err_on_missing_heartbeat: false)
    expect(msgs.opts[:err_on_missing_heartbeat]).to be(false)
    expect { msgs.next(timeout: 0.5) }.to raise_error(NATS::Timeout)
    expect(pulls_sent.size).to eql(1)

    server_stopped do
      # The heartbeats stop after a second, and it keeps waiting.
      expect { msgs.next(timeout: 2.5) }.to raise_error(NATS::Timeout)
    end
    # It pulled again for the heartbeats that stopped.
    eventually { expect(pulls.pending_queue.size).to be >= 1 }

    js.publish("hb.a", "0")
    expect(msgs.next(timeout: 5).data).to eql("0")
    expect(msgs.closed?).to be(false)
    msgs.stop
  end

  it "waits through missing heartbeats with each" do
    msgs = psub.messages(expires: 2, heartbeat: 0.5, err_on_missing_heartbeat: false)
    got = Queue.new
    reader = Thread.new do
      msgs.each { |msg| got << msg.data }
    rescue => e
      e
    end
    sleep 0.3

    server_stopped { sleep 1.5 }
    js.publish("hb.a", "0")
    expect(got.pop(timeout: 5)).to eql("0")
    msgs.stop
    expect(reader.value).to be(msgs)
  end

  it "does not change consume, which reports each missing heartbeat" do
    errors = Queue.new
    cc = psub.consume(expires: 2, heartbeat: 0.5, err_on_missing_heartbeat: false,
      error_handler: ->(e) { errors << e }) { |msg| msg }
    expect(cc.opts[:err_on_missing_heartbeat]).to be(true)
    eventually { expect(js.consumer_info("HB", "c1").num_waiting).to eql(1) }

    server_stopped do
      expect(errors.pop(timeout: 3)).to be_a(NATS::JetStream::Error::NoHeartbeat)
    end
    cc.stop
  end

  it "checks the option" do
    expect { psub.messages(err_on_missing_heartbeat: "no") }.to raise_error(ArgumentError, /err_on_missing_heartbeat/)
  end
end

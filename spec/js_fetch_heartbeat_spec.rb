# frozen_string_literal: true

describe "JetStream fetch with heartbeat" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-fetch-heartbeat")
    @s = NatsServerControl.new("nats://127.0.0.1:4733", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri, max_reconnect_attempts: -1, reconnect_time_wait: 0.2) }
  let(:js) { nc.jetstream }
  let(:sub) { js.pull_subscribe("hb.>", "c1", stream: "HB") }
  let(:pulls) { nc.subscribe("$JS.API.CONSUMER.MSG.NEXT.HB.c1") }

  before do
    js.add_stream(name: "HB", subjects: ["hb.>"])
    js.add_consumer("HB", durable_name: "c1", ack_policy: "explicit")
    sub
    pulls
    nc.flush
  end

  after { nc.close }

  def timed
    started = NATS::MonotonicTime.now
    [yield, NATS::MonotonicTime.since(started)]
  end

  def pulls_sent
    nc.flush
    Array.new(pulls.pending_queue.size) { JSON.parse(pulls.next_msg.data, symbolize_names: true) }
  end

  it "sends idle_heartbeat with the pull, in nanoseconds" do
    js.publish("hb.a", "1")
    sub.fetch(2, timeout: 1, heartbeat: 0.25)

    expect(pulls_sent.first).to include(batch: 2, idle_heartbeat: 250_000_000)
  end

  it "waits on through the heartbeats until its timeout" do
    _, elapsed = timed do
      expect { sub.fetch(1, timeout: 1.5, heartbeat: 0.2) }.to raise_error(NATS::Timeout)
    end
    expect(elapsed).to be_between(1.5, 2.2)
  end

  it "takes the messages that come between heartbeats" do
    Thread.new do
      sleep 0.8
      js.publish("hb.a", "late")
    end

    msgs, elapsed = timed { sub.fetch(1, timeout: 3, heartbeat: 0.2) }
    expect(msgs.map(&:data)).to eql(["late"])
    expect(elapsed).to be_between(0.8, 2)
  end

  it "keeps the heartbeats of fetches that wait at once apart" do
    fetches = Array.new(3) do
      Thread.new do
        sub.fetch(1, timeout: 1.5, heartbeat: 0.2)
      rescue => e
        e
      end
    end

    expect(fetches.map(&:value)).to all(be_a(NATS::Timeout))
  end

  it "raises NoHeartbeat when no heartbeat comes" do
    # The pull goes nowhere, so nothing comes back.
    allow(sub).to receive(:pull).and_return(nil)

    _, elapsed = timed do
      expect { sub.fetch(1, timeout: 5, heartbeat: 0.2) }.to raise_error(NATS::JetStream::Error::NoHeartbeat)
    end
    expect(elapsed).to be_between(0.4, 1)
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

  it "raises NoHeartbeat when the server stops sending" do
    fetch = Thread.new do
      sub.fetch(1, timeout: 5, heartbeat: 0.3)
    rescue => e
      e
    end
    eventually { expect(js.consumer_info("HB", "c1").num_waiting).to eql(1) }

    server_stopped do
      expect(fetch.value).to be_a(NATS::JetStream::Error::NoHeartbeat)
    end
  end

  it "returns the messages it got when the heartbeats stop" do
    js.publish("hb.a", "1")
    fetch = Thread.new { timed { sub.fetch(5, timeout: 5, heartbeat: 0.3) } }
    eventually { expect(js.consumer_info("HB", "c1").num_ack_pending).to eql(1) }

    msgs, elapsed = server_stopped { fetch.value }
    expect(msgs.map(&:data)).to eql(["1"])
    expect(elapsed).to be < 2
  end

  it "refuses an invalid heartbeat" do
    expect { sub.fetch(1, timeout: 1, heartbeat: 0.5) }.to raise_error(ArgumentError)
    expect { sub.fetch(1, timeout: 1, heartbeat: 0) }.to raise_error(ArgumentError)
    expect { sub.fetch(1, timeout: 1, heartbeat: "0.1") }.to raise_error(ArgumentError)
    expect { sub.fetch(1, no_wait: true, heartbeat: 0.1) }.to raise_error(ArgumentError)
    expect(pulls_sent).to be_empty
  end
end

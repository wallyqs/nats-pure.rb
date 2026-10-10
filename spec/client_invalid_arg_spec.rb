# frozen_string_literal: true

describe "Client - InvalidArg" do
  before(:all) do
    @tmpdir = Dir.mktmpdir("ruby-invalid-arg")
    @s = NatsServerControl.new("nats://127.0.0.1:4919", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect("nats://127.0.0.1:4919", reconnect: false) }

  after { nc.close }

  it "is an ArgumentError, as raised before" do
    expect(NATS::IO::InvalidArg.ancestors).to include(ArgumentError)
  end

  it "is raised for pending limits of zero, like SetPendingLimits of nats.go" do
    sub = nc.subscribe("foo")
    expect { sub.set_pending_limits(0, 1024) }.to raise_error(NATS::IO::InvalidArg, /nats: invalid argument/)
    expect { sub.set_pending_limits(10, 0) }.to raise_error(NATS::IO::InvalidArg)
    expect { sub.pending_msgs_limit = 0 }.to raise_error(NATS::IO::InvalidArg)
    expect { sub.pending_bytes_limit = 0 }.to raise_error(NATS::IO::InvalidArg)
    expect { nc.subscribe("bar", pending_msgs_limit: 0) }.to raise_error(NATS::IO::InvalidArg)

    # Negative limits do not limit, and are valid.
    sub.set_pending_limits(-1, -1)
    expect(sub.pending_limits).to eq([-1, -1])
  end

  it "is raised for an invalid fetch heartbeat, like PullHeartbeat of nats.go" do
    js = nc.jetstream
    js.add_stream(name: "INVARG", subjects: ["invarg.>"])
    js.add_consumer("INVARG", durable_name: "c1", ack_policy: "explicit")
    sub = js.pull_subscribe("invarg.>", "c1", stream: "INVARG")

    expect { sub.fetch(1, timeout: 1, heartbeat: 0) }.to raise_error(NATS::IO::InvalidArg, /heartbeat/)
    expect { sub.fetch(1, timeout: 1, heartbeat: 0.5) }.to raise_error(NATS::IO::InvalidArg, /half the timeout/)
  end
end

# frozen_string_literal: true

describe "Client - permission_err_on_subscribe" do
  before(:all) do
    @s = NatsServerControl.init_with_config_from_string(%(
      port = 4924
      authorization {
        users = [{user: "test", password: "test", permissions: {subscribe: {deny: "foo"}}}]
      }
    ), {"pid_file" => "/tmp/nats_permission_err_on_subscribe.pid", "host" => "127.0.0.1", "port" => 4924})
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
  end

  let(:errors) { Queue.new }

  def connect(**opts)
    nc = NATS::IO::Client.new
    nc.on_error { |e, sub| errors << [e, sub] }
    nc.connect("nats://test:test@127.0.0.1:4924", reconnect: false, **opts)
  end

  context "when enabled" do
    let(:nc) { connect(permission_err_on_subscribe: true) }

    after { nc.close }

    it "raises the permissions violation from next_msg of the refused subscription, like nats.go" do
      subs = Array.new(4) { |i| nc.subscribe(i.even? ? "foo" : "bar") }
      nc.flush

      subs.each do |sub|
        if sub.subject == "foo"
          expect { sub.next_msg(timeout: 0.1) }.to raise_error(NATS::IO::PermissionViolation, /Subscription to "foo"/)
          # And so on.
          expect { sub.next_msg(timeout: 0.1) }.to raise_error(NATS::IO::PermissionViolation)
        else
          expect { sub.next_msg(timeout: 0.1) }.to raise_error(NATS::Timeout)
        end
      end
    end

    it "wakes up a next_msg that waits" do
      sub = nc.subscribe("foo")
      started = NATS::MonotonicTime.now
      expect { sub.next_msg(timeout: 3) }.to raise_error(NATS::IO::PermissionViolation)
      expect(NATS::MonotonicTime.since(started)).to be < 2
    end

    it "gives on_error the subscription" do
      sub = nc.subscribe("foo") { |_msg| }
      e, errored = errors.pop(timeout: 2)
      expect(e).to be_a(NATS::IO::PermissionViolation)
      expect(errored).to equal(sub)
    end

    it "tells subscriptions apart by queue group" do
      plain = nc.subscribe("foo")
      queued = nc.subscribe("foo", queue: "q")
      nc.flush
      2.times { errors.pop(timeout: 2) }

      expect { queued.next_msg(timeout: 0.1) }.to raise_error(NATS::IO::PermissionViolation, /using queue "q"/)
      expect { plain.next_msg(timeout: 0.1) }.to raise_error(NATS::IO::PermissionViolation) { |e| expect(e.message).not_to include("queue") }
    end

    it "keeps the connection up" do
      nc.subscribe("foo")
      errors.pop(timeout: 2)
      sub = nc.subscribe("bar")
      nc.publish("bar", "hi")
      expect(sub.next_msg(timeout: 1).data).to eq("hi")
      expect(nc).to be_connected
    end
  end

  context "when disabled, as by default" do
    let(:nc) { connect }

    after { nc.close }

    it "gives on_error no subscription, and next_msg times out" do
      sub = nc.subscribe("foo")
      nc.flush
      e, errored = errors.pop(timeout: 2)
      expect(e).to be_a(NATS::IO::PermissionViolation)
      expect(errored).to be_nil
      expect { sub.next_msg(timeout: 0.1) }.to raise_error(NATS::Timeout)
    end
  end
end

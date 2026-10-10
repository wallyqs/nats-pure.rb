# frozen_string_literal: true

describe "Client - message and subscription errors" do
  before(:all) do
    @s = NatsServerControl.new("nats://127.0.0.1:4894", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
  end

  before do
    @errors = Queue.new
    @nc = NATS::IO::Client.new
    @nc.on_error { |e, sub| @errors << [e, sub] }
    @nc.connect(@s.uri)
  end

  after do
    @nc.close
  end

  def raw_hpub(subject, hdr, data)
    raw = TCPSocket.new("127.0.0.1", 4894)
    raw.gets # INFO
    raw.write("CONNECT {\"headers\":true,\"verbose\":false}\r\nHPUB #{subject} #{hdr.bytesize} #{hdr.bytesize + data.bytesize}\r\n#{hdr}#{data}\r\nPING\r\n")
    expect(raw.gets).to eql("PONG\r\n")
    raw.close
  end

  it "should deliver a message whose header cannot be decoded without it and report BadHeaderMsg" do
    sub = @nc.subscribe("bad.hdr")
    @nc.flush

    # The server passes these on as they are; nats.go fails to decode them.
    ["BAD/1.0\r\nK: v\r\n\r\n", "NATS/1.0\r\nno colon\r\n\r\n", "NATS/1.0 1\r\n\r\n"].each_with_index do |hdr, i|
      raw_hpub("bad.hdr", hdr, "data-#{i}")

      msg = sub.next_msg(timeout: 1)
      expect(msg.data).to eql("data-#{i}")
      expect(msg.header).to be_nil
      err, err_sub = @errors.pop
      expect(err).to be_a(NATS::IO::BadHeaderMsg)
      expect(err).to be_a(NATS::IO::ClientError)
      expect(err.message).to eql("nats: message could not decode headers")
      expect(err_sub).to eql(sub)
    end
    expect(@nc.last_error).to be_a(NATS::IO::BadHeaderMsg)

    # Like nats.go, a line without a name is skipped.
    raw_hpub("bad.hdr", "NATS/1.0 503\r\n: x\r\nK:v\r\n\r\n", "ok")
    msg = sub.next_msg(timeout: 1)
    expect(msg.header).to eql("Status" => "503", "K" => "v")
    expect(@errors).to be_empty
  end

  it "should raise MaxMessages from next_msg once the max messages were taken" do
    sub = @nc.subscribe("max", max: 2)
    3.times { @nc.publish("max", "x") }
    @nc.flush

    2.times { expect(sub.next_msg(timeout: 1).data).to eql("x") }
    started = NATS::MonotonicTime.now
    expect { sub.next_msg(timeout: 2) }.to raise_error(NATS::IO::MaxMessages, "nats: maximum messages delivered")
    expect(NATS::MonotonicTime.now - started).to be < 1
    expect(NATS::IO::MaxMessages.ancestors).to include(NATS::IO::BadSubscription)

    sub = @nc.subscribe("auto")
    sub.unsubscribe(1)
    expect { sub.next_msg(timeout: 0.1) }.to raise_error(NATS::Timeout)
    @nc.publish("auto", "y")
    expect(sub.next_msg(timeout: 1).data).to eql("y")
    expect { sub.next_msg(timeout: 2) }.to raise_error(NATS::IO::MaxMessages)
  end

  it "should raise BadSubscription from next_msg once unsubscribed and the messages were taken" do
    sub = @nc.subscribe("unsub")
    2.times { @nc.publish("unsub", "x") }
    @nc.flush
    sub.unsubscribe

    2.times { expect(sub.next_msg(timeout: 1).data).to eql("x") }
    expect { sub.next_msg(timeout: 2) }.to raise_error(NATS::IO::BadSubscription, "nats: invalid subscription")

    # A next_msg that waits gets it once the subscription goes.
    sub = @nc.subscribe("waiting")
    waiter = Thread.new do
      sub.next_msg(timeout: 5)
    rescue => e
      e
    end
    sleep 0.2
    started = NATS::MonotonicTime.now
    sub.unsubscribe
    expect(waiter.value).to be_a(NATS::IO::BadSubscription)
    expect(NATS::MonotonicTime.now - started).to be < 1

    sub = @nc.subscribe("drained")
    sub.drain
    sleep 0.1 while sub.draining?
    expect { sub.next_msg(timeout: 2) }.to raise_error(NATS::IO::BadSubscription)
  end

  it "should raise ConnectionClosedError from next_msg once the connection is closed" do
    nc = NATS.connect(@s.uri)
    sub = nc.subscribe("closing")
    waiter = Thread.new do
      sub.next_msg(timeout: 5)
    rescue => e
      e
    end
    sleep 0.2
    started = NATS::MonotonicTime.now
    nc.close
    expect(waiter.value).to be_a(NATS::IO::ConnectionClosedError)
    expect(NATS::MonotonicTime.now - started).to be < 2
    expect { sub.next_msg(timeout: 1) }.to raise_error(NATS::IO::ConnectionClosedError)
  end

  it "should raise MsgNoReply, MsgNotBound and InvalidMsg like nats.go" do
    sub = @nc.subscribe("respond")
    @nc.publish("respond", "no reply")
    msg = sub.next_msg(timeout: 1)

    expect { msg.respond("x") }.to raise_error(NATS::IO::MsgNoReply, "nats: message does not have a reply")
    expect { msg.respond("x") }.to raise_error(NATS::IO::BadSubject)
    expect { msg.respond_msg(NATS::Msg.new(data: "x")) }.to raise_error(NATS::IO::MsgNoReply)

    unbound = NATS::Msg.new(subject: "foo", reply: "bar", data: "x")
    expect { unbound.respond("x") }.to raise_error(NATS::IO::MsgNotBound, "nats: message is not bound to subscription/connection")
    expect { unbound.respond_msg(NATS::Msg.new(data: "x")) }.to raise_error(NATS::IO::MsgNotBound)

    expect { msg.respond_msg("x") }.to raise_error(NATS::IO::InvalidMsg)
    expect { @nc.publish_msg("x") }.to raise_error(NATS::IO::InvalidMsg, "nats: expected NATS::Msg, got String")
    expect { @nc.request_msg(nil) }.to raise_error(TypeError)
  end
end

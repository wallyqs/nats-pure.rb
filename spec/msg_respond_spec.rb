# frozen_string_literal: true

describe "Msg#respond and Msg#respond_msg" do
  before(:all) do
    @s = NatsServerControl.new("nats://127.0.0.1:4891", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
  end

  before do
    @nc = NATS.connect(@s.uri)
  end

  after do
    @nc.close
  end

  def request(subject, header)
    inbox = @nc.new_inbox
    replies = @nc.subscribe(inbox)
    @nc.publish_msg(NATS::Msg.new(subject: subject, reply: inbox, data: "ping", header: header))
    [inbox, replies.next_msg(timeout: 1)]
  end

  it "should respond with the data only, like Respond of nats.go" do
    @nc.subscribe("svc.respond") { |msg| msg.respond("pong") }
    @nc.flush

    inbox, resp = request("svc.respond", {"X-Req" => "1"})
    expect(resp.subject).to eql(inbox)
    expect(resp.data).to eql("pong")
    # Not the headers nor the reply subject of the request.
    expect(resp.header).to be_nil
    expect(resp.reply).to be_nil

    _, resp = request("svc.respond", nil)
    expect(resp.data).to eql("pong")
    expect(resp.header).to be_nil
  end

  it "should respond to the reply subject with respond_msg, like RespondMsg of nats.go" do
    sent = Queue.new
    @nc.subscribe("svc.respond_msg") do |msg|
      out = NATS::Msg.new(subject: "elsewhere", data: "pong", header: {"X-Resp" => msg.header["X-Req"]})
      msg.respond_msg(out)
      sent << out
    end
    elsewhere = @nc.subscribe("elsewhere")
    @nc.flush

    inbox, resp = request("svc.respond_msg", {"X-Req" => "42"})
    expect(resp.subject).to eql(inbox)
    expect(resp.data).to eql("pong")
    expect(resp.header).to eql("X-Resp" => "42")
    expect(resp.reply).to be_nil
    expect(sent.pop.subject).to eql(inbox)
    expect { elsewhere.next_msg(timeout: 0.2) }.to raise_error(NATS::Timeout)
  end

  it "should respond to requests made with request and request_msg" do
    @nc.subscribe("svc.req") do |msg|
      if msg.header
        msg.respond_msg(NATS::Msg.new(data: "with header", header: {"A" => "b"}))
      else
        msg.respond("plain")
      end
    end
    @nc.flush

    expect(@nc.request("svc.req", "x", timeout: 1).data).to eql("plain")
    resp = @nc.request_msg(NATS::Msg.new(subject: "svc.req", header: {"Q" => "1"}), timeout: 1)
    expect(resp.data).to eql("with header")
    expect(resp.header).to eql("A" => "b")
  end

  it "should raise TypeError for a response that is not a NATS::Msg" do
    sub = @nc.subscribe("svc.type")
    @nc.publish("svc.type", "x", "reply")
    msg = sub.next_msg(timeout: 1)

    expect { msg.respond_msg("foo") }.to raise_error(TypeError)
  end
end

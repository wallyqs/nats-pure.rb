# frozen_string_literal: true

describe "Msg#== and Msg#size" do
  before(:all) do
    @s = NatsServerControl.new("nats://127.0.0.1:4890", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
  end

  it "should compare the subject, reply, header and data like Msg.Equal of nats.go" do
    a = NATS::Msg.new(subject: "foo", reply: "bar", data: "hi", header: {"A" => "1", "B" => %w[2 3]})
    b = NATS::Msg.new(subject: "foo", reply: "bar", data: "hi".b, header: {"B" => %w[2 3], "A" => ["1"]})

    expect(a).to eq(b)
    expect(a).to eql(b)
    expect(a.hash).to eql(b.hash)
    expect([a, b].uniq.size).to eql(1)

    expect(a).not_to eq(NATS::Msg.new(subject: "foo2", reply: "bar", data: "hi", header: b.header))
    expect(a).not_to eq(NATS::Msg.new(subject: "foo", reply: "bar2", data: "hi", header: b.header))
    expect(a).not_to eq(NATS::Msg.new(subject: "foo", reply: "bar", data: "hi2", header: b.header))
    expect(a).not_to eq(NATS::Msg.new(subject: "foo", reply: "bar", data: "hi", header: {"A" => "1"}))
    expect(a).not_to eq(NATS::Msg.new(subject: "foo", reply: "bar", data: "hi", header: {"A" => "1", "B" => %w[3 2]}))
    expect(a).not_to eq(NATS::Msg.new(subject: "foo", reply: "bar", data: "hi"))
    expect(a).not_to eq("foo")
    expect(a).not_to eq(nil)

    # Like the empty strings and nil headers of Go.
    expect(NATS::Msg.new(subject: "foo")).to eq(NATS::Msg.new(subject: "foo", reply: "", data: "", header: {}))
  end

  it "should not compare the connection and the subscription of a received message" do
    nc = NATS.connect(@s.uri)
    sub = nc.subscribe("equal")
    sent = NATS::Msg.new(subject: "equal", reply: "inbox", data: "hello", header: {"X" => %w[1 2], "Y" => "z"})
    nc.publish_msg(sent)

    msg = sub.next_msg(timeout: 1)
    expect(msg.sub).to eql(sub)
    expect(msg).to eq(sent)
    expect(sent).to eq(msg)
    expect({sent => 1}[msg]).to eql(1)

    nc.close
  end

  it "should count the subject, reply, header and data like Msg.Size of nats.go" do
    expect(NATS::Msg.new(subject: "foo", data: "hello").size).to eql(8)
    expect(NATS::Msg.new(subject: "foo", reply: "bar", data: "héllo").size).to eql(12)

    msg = NATS::Msg.new(subject: "foo", reply: "bar", data: "hi", header: {"A" => "1", "B" => %w[2 3]})
    hdr = "NATS/1.0\r\nA: 1\r\nB: 2\r\nB: 3\r\n\r\n"
    expect(msg.size).to eql(3 + 3 + hdr.bytesize + 2)

    # An empty header is not sent.
    expect(NATS::Msg.new(subject: "foo", data: "hi", header: {}).size).to eql(5)
  end

  it "should take the size of a received message as it came" do
    nc = NATS.connect(@s.uri)
    sub = nc.subscribe("size.>")
    nc.flush

    sent = NATS::Msg.new(subject: "size.hdr", reply: "inbox", data: "hello", header: {"X" => %w[1 2], "Y" => "z"})
    nc.publish_msg(sent)
    nc.publish("size.plain", "world", "reply")

    # Headers sent by another client, with a status, as nats.go counts them.
    hdr = "NATS/1.0 100 Idle\r\nK:v\r\n\r\n"
    raw = TCPSocket.new("127.0.0.1", 4890)
    raw.gets # INFO
    raw.write("CONNECT {\"headers\":true,\"verbose\":false}\r\nHPUB size.raw #{hdr.bytesize} #{hdr.bytesize + 2}\r\n#{hdr}hi\r\nPING\r\n")
    expect(raw.gets).to eql("PONG\r\n")
    raw.close

    msg = sub.next_msg(timeout: 1)
    expect(msg.size).to eql(sent.size)
    expect(msg.size).to eql("size.hdr".bytesize + "inbox".bytesize + "NATS/1.0\r\nX: 1\r\nX: 2\r\nY: z\r\n\r\n".bytesize + 5)

    msg = sub.next_msg(timeout: 1)
    expect(msg.size).to eql("size.plain".bytesize + "reply".bytesize + "world".bytesize)

    msg = sub.next_msg(timeout: 1)
    expect(msg.header).to eql("Status" => "100", "Description" => "Idle", "K" => "v")
    expect(msg.size).to eql("size.raw".bytesize + hdr.bytesize + 2)

    nc.close
  end
end

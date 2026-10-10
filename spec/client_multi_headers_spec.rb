# frozen_string_literal: true

require "tmpdir"

describe "Client - repeated header names" do
  before(:all) do
    @tmpdir = Dir.mktmpdir("nats-multi-headers")
    @s = NatsServerControl.new("nats://127.0.0.1:4875", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
    FileUtils.rm_rf(@tmpdir)
  end

  it "should parse a repeated header name into an Array of its values" do
    nc = NATS.connect(@s.uri)
    sub = nc.subscribe("raw.headers")
    nc.flush

    # Publish as nats.go does for http.Header{"X-A": {"1", "2"}}.
    hdr = "NATS/1.0\r\nX-A: 1\r\nX-B: only\r\nX-A: 2\r\nX-A: 3\r\n\r\n"
    raw = TCPSocket.new("127.0.0.1", 4875)
    raw.gets # INFO
    raw.write("CONNECT {\"headers\":true,\"verbose\":false}\r\nHPUB raw.headers #{hdr.bytesize} #{hdr.bytesize + 2}\r\n#{hdr}hi\r\nPING\r\n")
    expect(raw.gets).to eql("PONG\r\n")
    raw.close

    msg = sub.next_msg(timeout: 2)
    expect(msg.data).to eql("hi")
    # Names that come once stay Strings.
    expect(msg.header).to eql("X-A" => %w[1 2 3], "X-B" => "only")

    nc.close
  end

  it "should publish one header line for each value of an Array" do
    nc = NATS.connect(@s.uri)
    sub = nc.subscribe("multi.headers")

    nc.publish("multi.headers", "hi", header: {"X-A" => %w[1 2], "X-B" => "3", "X-C" => ["4"]})
    msg = sub.next_msg(timeout: 2)
    expect(msg.header).to eql("X-A" => %w[1 2], "X-B" => "3", "X-C" => "4")

    nc.publish_msg(NATS::Msg.new(subject: "multi.headers", header: {"X-A" => %w[a b c]}))
    expect(sub.next_msg(timeout: 2).header).to eql("X-A" => %w[a b c])

    nc.close
  end

  it "should take Arrays in the headers of requests and responses" do
    nc = NATS.connect(@s.uri)
    nc.subscribe("multi.svc") do |msg|
      msg.respond_msg(NATS::Msg.new(subject: msg.reply, data: "ok", header: {"X-Got" => msg.header["X-A"]}))
    end

    resp = nc.request("multi.svc", "hi", header: {"X-A" => %w[1 2]}, timeout: 2)
    expect(resp.header).to eql("X-Got" => %w[1 2])

    resp = nc.request_msg(NATS::Msg.new(subject: "multi.svc", header: {"X-A" => %w[3 4 5]}), timeout: 2)
    expect(resp.header).to eql("X-Got" => %w[3 4 5])

    nc.close
  end

  it "should keep repeated header names of JetStream messages" do
    nc = NATS.connect(@s.uri)
    js = nc.jetstream
    js.add_stream(name: "MULTIHDR", subjects: ["mh.>"], allow_direct: true)

    js.publish("mh.a", "one", header: {"X-A" => %w[1 2], "X-B" => "3"})
    expected = {"X-A" => %w[1 2], "X-B" => "3"}

    # Pulled messages.
    psub = js.pull_subscribe("mh.a", "multi")
    msg = psub.fetch(1, timeout: 2).first
    expect(msg.header).to eql(expected)

    # Messages of the stream, through the API and direct gets.
    expect(js.get_msg("MULTIHDR", seq: 1).headers).to eql(expected)
    direct = js.get_msg("MULTIHDR", seq: 1, direct: true).headers
    expect(direct.slice("X-A", "X-B")).to eql(expected)
    expect(direct["Nats-Stream"]).to eql("MULTIHDR")

    # Its size, for max_bytes, counts a line for each value.
    hdr_size = "NATS/1.0\r\nX-A: 1\r\nX-A: 2\r\nX-B: 3\r\n\r\n".bytesize
    expect(NATS::JetStream.const_get(:JS).msg_size(msg)).to eql(msg.subject.bytesize + msg.reply.bytesize + 3 + hdr_size)

    js.delete_stream("MULTIHDR")
    nc.close
  end
end

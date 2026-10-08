# frozen_string_literal: true

describe "NATS.new_inbox" do
  before(:all) do
    @s = NatsServerControl.new("nats://127.0.0.1:4892", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
  end

  it "should return unique inboxes like NewInbox of nats.go" do
    expect(NATS.new_inbox).to match(/\A_INBOX\.[0-9A-Za-z]{22}\z/)

    inboxes = Array.new(4) { Thread.new { Array.new(1000) { NATS.new_inbox } } }.flat_map(&:value)
    expect(inboxes.uniq.size).to eql(4000)
  end

  it "should take a prefix like the custom_inbox_prefix option" do
    expect(NATS.new_inbox("_MY.INBOX")).to match(/\A_MY\.INBOX\.[0-9A-Za-z]{22}\z/)

    ["", "a.>", "a.*", "a.", ".a"].each do |prefix|
      expect { NATS.new_inbox(prefix) }.to raise_error(NATS::IO::ClientError, /custom inbox may not/)
      expect do
        NATS::Client.new.connect(@s.uri, custom_inbox_prefix: prefix, reconnect: false)
      end.to raise_error(NATS::IO::ClientError, /custom inbox may not/)
    end
  end

  it "should give inboxes that replies come to" do
    nc = NATS.connect(@s.uri, custom_inbox_prefix: "_CUSTOM")
    expect(nc.new_inbox).to match(/\A_CUSTOM\.[0-9A-Za-z]{22}\z/)
    nc.subscribe("svc") { |msg| msg.respond("pong") }

    [NATS.new_inbox, NATS.new_inbox("_CUSTOM"), nc.new_inbox].each do |inbox|
      replies = nc.subscribe(inbox)
      nc.publish("svc", "ping", inbox)
      expect(replies.next_msg(timeout: 1).data).to eql("pong")
    end

    expect(nc.request("svc", "ping", timeout: 1).data).to eql("pong")
    nc.close
  end

  it "should not give a forked process the inboxes of its parent", skip: !Process.respond_to?(:fork) do
    NATS.new_inbox
    reader, writer = IO.pipe
    pid = fork do
      reader.close
      writer.puts(NATS.new_inbox)
      writer.close
      exit!(0)
    end
    writer.close
    child = reader.gets.chomp
    Process.wait(pid)

    expect(child).to match(/\A_INBOX\./)
    expect(NATS.new_inbox).not_to eql(child)
  end
end

# frozen_string_literal: true

describe "Client - new_resp_inbox" do
  before(:all) do
    @server = NatsServerControl.new("nats://127.0.0.1:4945", "/tmp/test-nats-4945.pid", "-a 127.0.0.1")
    @server.start_server(true)
  end

  after(:all) { @server.kill_server }

  def prefix_of(inbox)
    inbox.split(".")[0..-2].join(".")
  end

  it "should return inboxes under the prefix of the response subscription, like NewRespInbox of nats.go" do
    nc = NATS.connect("nats://127.0.0.1:4945", reconnect: false)
    subs = nc.num_subscriptions

    a = nc.new_resp_inbox
    b = nc.new_resp_inbox
    expect(a).to match(/\A_INBOX\.[A-Za-z0-9]{22}\.[A-Za-z0-9]{22}\z/)
    expect(prefix_of(a)).to eql(prefix_of(b))
    expect(a).not_to eql(b)
    # Like nats.go, it does not subscribe; the first request does.
    expect(nc.num_subscriptions).to eql(subs)

    replies = []
    nc.subscribe("svc") do |msg|
      replies << msg.reply
      msg.respond("ok")
    end
    expect(nc.request("svc", "hi").data).to eql("ok")
    expect(prefix_of(replies.first)).to eql(prefix_of(a))
    expect(nc.num_subscriptions).to eql(subs + 2)
    expect(prefix_of(nc.new_resp_inbox)).to eql(prefix_of(a))
    nc.close
  end

  it "should use the custom inbox prefix" do
    nc = NATS.connect("nats://127.0.0.1:4945", reconnect: false, custom_inbox_prefix: "_MY.app")
    expect(nc.new_resp_inbox).to start_with("_MY.app.")
    expect(nc.new_resp_inbox.split(".").size).to eql(4)
    nc.close
  end

  it "should deliver messages to an inbox to its subscription, without upsetting requests" do
    nc = NATS.connect("nats://127.0.0.1:4945", reconnect: false)
    nc.subscribe("svc") { |msg| msg.respond("ok") }
    expect(nc.request("svc", "hi").data).to eql("ok")

    inbox = nc.new_resp_inbox
    sub = nc.subscribe(inbox)
    10.times { nc.publish(inbox, "x") }
    nc.flush
    expect(sub.next_msg(timeout: 1).data).to eql("x")

    # The response subscription takes them too, before the response to the
    # next request, but no request waits for them, so it keeps none.
    expect(nc.request("svc", "again").data).to eql("ok")
    expect(nc.instance_variable_get(:@resp_map)).to be_empty
    nc.close
  end
end

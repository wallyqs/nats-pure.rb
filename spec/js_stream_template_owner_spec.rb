# frozen_string_literal: true

describe "JetStream StreamConfig template_owner" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-template-owner")
    @s = NatsServerControl.new("nats://127.0.0.1:4742", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  it "is a member of StreamConfig, nil unless set" do
    expect(NATS::JetStream::API::StreamConfig.members).to include(:template_owner)
    expect(NATS::JetStream::API::StreamConfig.new(name: "S").template_owner).to be_nil
    expect(NATS::JetStream::API::StreamConfig.new(name: "S", template_owner: "T").template_owner).to eql("T")
  end

  it "is not sent unless set, so servers that do not know it take the config" do
    resp = js.add_stream(name: "S", subjects: ["s"])
    expect(resp.config.template_owner).to be_nil
    expect(js.stream_info("S").config.template_owner).to be_nil

    resp = js.add_stream(name: "E", subjects: ["e"], template_owner: "")
    expect(resp.config.name).to eql("E")
    expect(js.update_stream(resp.config.to_h.merge(max_msgs: 10)).config.max_msgs).to eql(10)
  end

  it "is sent when set, which servers without templates refuse, as with nats.go" do
    expect do
      js.add_stream(name: "T", subjects: ["t"], template_owner: "TEMPLATE")
    end.to raise_error(NATS::JetStream::Error::BadRequest, /template_owner/)
  end

  # A server with templates, such as v2.12, sends the template of a stream,
  # which a responder under another API prefix stands in for.
  it "round-trips the template of a stream from a server that has templates" do
    js.add_stream(name: "OLD", subjects: ["old"])
    info = JSON.parse(nc.request("$JS.API.STREAM.INFO.OLD", "", timeout: 2).data)
    info["config"]["template_owner"] = "TEMPLATE"
    requests = Queue.new
    nc.subscribe("old.STREAM.INFO.OLD") { |msg| msg.respond(info.to_json) }
    nc.subscribe("old.STREAM.UPDATE.OLD") do |msg|
      requests << JSON.parse(msg.data)
      msg.respond(info.merge("type" => "io.nats.jetstream.api.v1.stream_update_response").to_json)
    end
    nc.flush

    old = nc.jetstream(prefix: "old")
    config = old.stream_info("OLD").config
    expect(config.template_owner).to eql("TEMPLATE")

    resp = old.update_stream(config)
    expect(requests.pop(timeout: 2)["template_owner"]).to eql("TEMPLATE")
    expect(resp.config.template_owner).to eql("TEMPLATE")
  end
end

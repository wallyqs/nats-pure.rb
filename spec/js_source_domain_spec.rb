# frozen_string_literal: true

describe "JetStream stream sources from other domains" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-source-domain")
    hub_conf = File.join(@tmpdir, "hub.conf")
    File.write(hub_conf, <<~CONF)
      jetstream { store_dir: "#{@tmpdir}/hub", domain: HUB }
      leafnodes { listen: "127.0.0.1:7748" }
    CONF
    leaf_conf = File.join(@tmpdir, "leaf.conf")
    File.write(leaf_conf, <<~CONF)
      jetstream { store_dir: "#{@tmpdir}/leaf", domain: LEAF }
      leafnodes { remotes = [{ url: "nats-leaf://127.0.0.1:7748" }] }
    CONF
    @hub = NatsServerControl.new("nats://127.0.0.1:4748", "/tmp/test-nats.pid", "-c #{hub_conf}")
    @hub.start_server(true)
    @leaf = NatsServerControl.new("nats://127.0.0.1:4749", "/tmp/test-nats.pid", "-c #{leaf_conf}")
    @leaf.start_server(true)

    @hnc = NATS.connect(@hub.uri)
    @lnc = NATS.connect(@leaf.uri)
    # Wait for the leafnode connection, over which the domains reach each other.
    deadline = Time.now + 10
    begin
      @lnc.jetstream(domain: "HUB").account_info(timeout: 0.5)
    rescue NATS::Timeout, NATS::JetStream::Error::ServiceUnavailable
      retry if Time.now < deadline
      raise
    end

    hjs = @hnc.jetstream
    hjs.add_stream(name: "TEST", subjects: ["foo"])
    hjs.publish("foo", "msg1")
    hjs.publish("foo", "msg2")
  end

  after do
    @hnc.close
    @lnc.close
    @leaf.kill_server
    @hub.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:ljs) { @lnc.jetstream }

  def wait_for_messages(stream, count)
    deadline = Time.now + 10
    sleep 0.05 until ljs.stream_info(stream).state.messages == count || Time.now > deadline
    ljs.stream_info(stream).state.messages
  end

  it "mirrors a stream of another domain" do
    config = {name: "MIRROR", mirror: {name: "TEST", domain: "HUB"}}
    resp = ljs.add_stream(config)
    expect(resp.config.mirror[:external]).to include(api: "$JS.HUB.API")
    expect(resp.config.mirror).not_to have_key(:domain)
    # The config given is left as it was.
    expect(config).to eql(name: "MIRROR", mirror: {name: "TEST", domain: "HUB"})

    expect(wait_for_messages("MIRROR", 2)).to eql(2)
    @hnc.jetstream.publish("foo", "msg3")
    expect(wait_for_messages("MIRROR", 3)).to eql(3)
  end

  it "sources streams of other domains" do
    sources = [{name: "TEST", domain: "HUB"}]
    config = NATS::JetStream::API::StreamConfig.new(name: "SOURCED", sources: sources)
    resp = ljs.add_stream(config)
    expect(resp.config.sources.first[:external]).to include(api: "$JS.HUB.API")
    expect(config.sources).to eql([{name: "TEST", domain: "HUB"}])
    expect(wait_for_messages("SOURCED", 2)).to eql(2)

    # As in an update.
    ljs.update_stream(name: "SOURCED", sources: [{"name" => "TEST", "domain" => "HUB", "filter_subject" => "foo"}])
    info = ljs.stream_info("SOURCED")
    expect(info.config.sources.first[:external]).to include(api: "$JS.HUB.API")
    expect(info.config.sources.first[:filter_subject]).to eql("foo")
  end

  it "takes no domain with an external" do
    expect do
      ljs.add_stream(name: "BAD", mirror: {name: "TEST", domain: "HUB", external: {api: "$JS.HUB.API"}})
    end.to raise_error(ArgumentError, "nats: domain and external are both set")
    expect do
      ljs.create_or_update_stream(name: "BAD", sources: [{name: "TEST", domain: "HUB", external: {api: "$JS.HUB.API"}}])
    end.to raise_error(ArgumentError)
  end

  it "ignores an empty domain" do
    resp = @hnc.jetstream.add_stream(name: "LOCAL", sources: [{name: "TEST", domain: ""}])
    expect(resp.config.sources.first[:external]).to be_nil
  end
end

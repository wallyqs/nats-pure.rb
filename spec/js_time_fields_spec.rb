# frozen_string_literal: true

describe "JetStream time fields" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-times")
    @s = NatsServerControl.new("nats://127.0.0.1:4762", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  let(:rfc3339_nanos) { /\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z\z/ }

  # Publishes before and after a point in time, which it returns.
  def publish_around(subject)
    js.publish(subject, "before")
    sleep 0.05
    start = Time.now
    sleep 0.05
    js.publish(subject, "after")
    start
  end

  describe "opt_start_time" do
    it "sends a Time of a consumer as RFC 3339 with nanoseconds" do
      js.add_stream(name: "T", subjects: ["t.>"])
      start = publish_around("t.a")
      creates = nc.subscribe("$JS.API.CONSUMER.CREATE.T.>")
      nc.flush

      info = js.add_consumer("T", durable_name: "c", deliver_policy: "by_start_time", opt_start_time: start)
      sent = JSON.parse(creates.next_msg.data, symbolize_names: true)[:config][:opt_start_time]
      expect(sent).to match(rfc3339_nanos)
      expect(Time.iso8601(sent)).to eql(start.getutc)
      expect(Time.parse(info.config.opt_start_time)).to eql(start.getutc)

      psub = js.pull_subscribe("t.a", "c", stream: "T")
      expect(psub.fetch(2, timeout: 1).map(&:data)).to eql(["after"])
    end

    it "sends a Time of a stream source or mirror as RFC 3339 with nanoseconds" do
      js.add_stream(name: "ORIGIN", subjects: ["origin"])
      start = publish_around("origin")
      creates = nc.subscribe("$JS.API.STREAM.CREATE.>")
      nc.flush

      js.add_stream(name: "SOURCED", sources: [{name: "ORIGIN", opt_start_time: start}])
      js.add_stream(name: "MIRROR", mirror: {name: "ORIGIN", opt_start_time: start})
      sent = Array.new(2) { JSON.parse(creates.next_msg.data, symbolize_names: true) }
      expect(sent[0][:sources][0][:opt_start_time]).to match(rfc3339_nanos)
      expect(sent[1][:mirror][:opt_start_time]).to match(rfc3339_nanos)

      %w[SOURCED MIRROR].each do |stream|
        eventually { expect(js.stream_info(stream).state.messages).to eql(1) }
        expect(js.get_msg(stream, seq: js.stream_info(stream).state.first_seq).data).to eql("after")
      end
    end

    it "leaves a String as it is" do
      js.add_stream(name: "T", subjects: ["t.>"])
      info = js.add_consumer("T", durable_name: "c", deliver_policy: "by_start_time",
        opt_start_time: "2020-01-02T03:04:05.123456789Z")
      expect(Time.parse(info.config.opt_start_time)).to eql(Time.utc(2020, 1, 2, 3, 4, Rational(5_123_456_789, 1_000_000_000)))
    end
  end

  describe "time readers" do
    before { js.add_stream(name: "T", subjects: ["t.>"]) }

    it "parses the first and last times of a stream" do
      state = js.stream_info("T").state
      expect(state.first_time).to be_nil
      expect(state.last_time).to be_nil

      js.publish("t.a", "1")
      sleep 0.01
      js.publish("t.a", "2")
      psub = js.pull_subscribe("t.a", "c")
      first, last = psub.fetch(2)

      state = js.stream_info("T").state
      expect(state.first_ts).to be_a(String)
      expect(state.first_time).to eql(first.metadata.timestamp)
      expect(state.last_time).to eql(last.metadata.timestamp)
    end

    it "parses the last activity of a consumer" do
      js.publish("t.a", "1")
      psub = js.pull_subscribe("t.a", "c")
      info = psub.consumer_info
      expect(info.delivered.last_active_time).to be_nil

      before = Time.now
      psub.fetch(1).first.ack_sync
      info = psub.consumer_info
      expect(info.delivered.last_active).to be_a(String)
      expect(info.delivered.last_active_time).to be_between(before - 1, Time.now + 1)
      expect(info.ack_floor.last_active_time).to be_between(before - 1, Time.now + 1)
    end

    it "parses when a cluster change started" do
      info = NATS::JetStream::API::StreamInfo.new(
        config: {name: "S"}, state: {messages: 0}, created: "2026-01-01T00:00:00Z",
        cluster: {leader: "n1", leader_since: "2026-01-02T00:00:00.5Z",
                  desired: {created: "2026-01-03T00:00:00Z", name: "C", replicas: [{name: "n2", peer: "p2"}]}}
      )

      expect(info.cluster).to eql({leader: "n1", leader_since: "2026-01-02T00:00:00.5Z",
        desired: {created: "2026-01-03T00:00:00Z", name: "C", replicas: [{name: "n2", peer: "p2"}]}})
      expect(info.cluster.leader_since_time).to eql(Time.utc(2026, 1, 2, 0, 0, 0.5))
      expect(info.cluster[:desired]).to be_a(NATS::JetStream::API::DesiredClusterInfo)
      expect(info.cluster[:desired].created_time).to eql(Time.utc(2026, 1, 3))
    end
  end

  describe "in a cluster" do
    before do
      @cluster_dirs = Array.new(3) { Dir.mktmpdir("ruby-js-times-cluster") }
      routes = (1..3).map { |i| "nats://127.0.0.1:#{6790 + i}" }.join(",")
      @nodes = @cluster_dirs.each_with_index.map do |dir, i|
        NatsServerControl.new("nats://127.0.0.1:#{4790 + i + 1}", "/tmp/test-nats.pid",
          "-a 127.0.0.1 -js -sd=#{dir} -n n#{i + 1} --cluster_name TIMES " \
          "--cluster nats://127.0.0.1:#{6790 + i + 1} --routes #{routes}")
      end
      @nodes.each { |node| node.start_server(true) }
    end

    after do
      @nodes.each(&:kill_server)
      @cluster_dirs.each { |dir| FileUtils.remove_entry(dir) }
    end

    it "parses when the leaders of a stream and a consumer were elected" do
      cnc = NATS.connect(@nodes.first.uri)
      cjs = cnc.jetstream
      before = Time.now
      eventually(timeout: 30) { expect { cjs.add_stream(name: "L", subjects: ["l"], num_replicas: 3) }.not_to raise_error }
      cjs.add_consumer("L", durable_name: "c")

      [cjs.stream_info("L").cluster, cjs.consumer_info("L", "c").cluster].each do |cluster|
        expect(cluster).to be_a(NATS::JetStream::API::ClusterInfo)
        expect(cluster).to be_a(Hash)
        expect(cluster[:leader_since]).to be_a(String)
        expect(cluster.leader_since_time).to be_between(before - 1, Time.now + 1)
      end
    ensure
      cnc&.close
    end
  end
end

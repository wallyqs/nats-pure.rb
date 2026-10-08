# frozen_string_literal: true

describe "JetStream client trace" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-client-trace")
    @s = NatsServerControl.new("nats://127.0.0.1:4750", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:sent) { [] }
  let(:received) { [] }
  let(:trace) do
    {
      request_sent: ->(subject, payload) { sent << [subject, payload] },
      response_received: ->(subject, payload, header) { received << [subject, JSON.parse(payload), header] }
    }
  end

  after { nc.close }

  it "traces the requests to the JetStream API and their responses" do
    js = nc.jetstream(client_trace: trace)
    js.add_stream(name: "T", subjects: ["t"])
    js.stream_info("T")

    expect(sent.map(&:first)).to eql(["$JS.API.STREAM.CREATE.T", "$JS.API.STREAM.INFO.T"])
    expect(JSON.parse(sent[0][1])).to include("name" => "T", "subjects" => ["t"])
    expect(sent[1][1]).to eql("")

    expect(received.map(&:first)).to eql(["$JS.API.STREAM.CREATE.T", "$JS.API.STREAM.INFO.T"])
    expect(received[0][1]).to include("type" => "io.nats.jetstream.api.v1.stream_create_response")
    expect(received[1][1]).to include("type" => "io.nats.jetstream.api.v1.stream_info_response")
    expect(received[1][1]["config"]).to include("name" => "T")
  end

  it "traces the error responses" do
    js = nc.jetstream(client_trace: trace)
    expect { js.stream_info("MISSING") }.to raise_error(NATS::JetStream::Error::StreamNotFound)
    expect(sent.map(&:first)).to eql(["$JS.API.STREAM.INFO.MISSING"])
    expect(received.first[1]["error"]).to include("err_code" => 10059)
  end

  it "traces with the API prefix of the domain" do
    js = nc.jetstream(domain: "hub", client_trace: trace)
    expect { js.account_info(timeout: 0.5) }.to raise_error(NATS::JetStream::Error::ServiceUnavailable)
    expect(sent).to eql([["$JS.hub.API.INFO", ""]])
    # No response came.
    expect(received).to eql([])
  end

  it "traces the direct gets, with the headers of the response" do
    js = nc.jetstream(client_trace: {
      request_sent: ->(subject, payload) { sent << [subject, payload] },
      response_received: ->(subject, payload, header) { received << [subject, payload, header] }
    })
    js.add_stream(name: "D", subjects: ["d.>"], allow_direct: true)
    js.publish("d.a", "data")
    sent.clear
    received.clear

    expect(js.get_msg("D", seq: 1, direct: true).data).to eql("data")
    expect(sent).to eql([["$JS.API.DIRECT.GET.D", {seq: 1}.to_json]])
    subject, payload, header = received.first
    expect(subject).to eql("$JS.API.DIRECT.GET.D")
    expect(payload).to eql("data")
    expect(header).to include("Nats-Stream" => "D", "Nats-Subject" => "d.a", "Nats-Sequence" => "1")
  end

  it "traces the requests of the handles and of KV" do
    js = nc.jetstream(client_trace: trace)
    js.add_stream(name: "H", subjects: ["h"])
    js.stream("H").create_consumer(durable_name: "c").info
    kv = js.create_key_value(bucket: "B")
    kv.put("k", "v")
    kv.get("k")
    expect(sent.map(&:first)).to include(
      "$JS.API.STREAM.INFO.H", "$JS.API.CONSUMER.CREATE.H.c", "$JS.API.CONSUMER.INFO.H.c",
      "$JS.API.STREAM.CREATE.KV_B", "$JS.API.STREAM.MSG.GET.KV_B"
    )
    # Publishes, as that of the put, are not traced, as in nats.go.
    expect(sent.map(&:first)).not_to include("$KV.B.k")
  end

  it "passes the header only to callbacks that take it" do
    calls = []
    js = nc.jetstream(client_trace: {
      response_received: proc { |subject, payload| calls << [subject, payload.class] }
    })
    js.account_info
    expect(calls).to eql([["$JS.API.INFO", String]])

    calls.clear
    js = nc.jetstream(client_trace: {response_received: ->(subject, payload) { calls << subject }})
    js.account_info
    expect(calls).to eql(["$JS.API.INFO"])

    js = nc.jetstream(client_trace: {response_received: ->(*args) { calls << args.size }})
    js.account_info
    expect(calls.last).to eql(3)
  end

  it "does not trace without the option" do
    js = nc.jetstream
    expect { js.account_info }.not_to raise_error
  end

  it "checks the option" do
    expect { nc.jetstream(client_trace: proc {}) }.to raise_error(ArgumentError, /client_trace/)
    expect { nc.jetstream(client_trace: {request_sent: "x"}) }.to raise_error(ArgumentError, /request_sent/)
    expect { nc.jetstream(client_trace: {sent: proc {}}) }.to raise_error(ArgumentError, /:sent/)
  end
end

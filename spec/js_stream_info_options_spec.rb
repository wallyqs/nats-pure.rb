# frozen_string_literal: true

describe "JetStream stream_info options" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-stream-info-options")
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

  before do
    nc.jsm.add_stream(name: "ORDERS", subjects: ["orders.>"])
    js.publish("orders.eu.1", "a")
    js.publish("orders.eu.1", "b")
    js.publish("orders.eu.2", "c")
    js.publish("orders.us.1", "d")
    js.publish("orders.us.1", "e")
    js.publish("orders.us.1", "f")
  end

  it "decodes the state of the stream" do
    nc.jsm.delete_msg("ORDERS", 2)
    nc.jsm.delete_msg("ORDERS", 4)

    state = nc.jsm.stream_info("ORDERS").state
    expect(state.messages).to eql(4)
    expect(state.num_subjects).to eql(3)
    expect(state.num_deleted).to eql(2)
    # Only given when asked for.
    expect(state.deleted).to be_nil
    expect(state.subjects).to be_nil
    expect(state.lost).to be_nil
  end

  it "lists the deleted messages with deleted_details" do
    nc.jsm.delete_msg("ORDERS", 2)
    nc.jsm.secure_delete_msg("ORDERS", 5)

    state = nc.jsm.stream_info("ORDERS", deleted_details: true).state
    expect(state.deleted).to eql([2, 5])
    expect(state.num_deleted).to eql(2)

    expect(nc.jsm.stream_info("ORDERS", deleted_details: false).state.deleted).to be_nil
  end

  it "counts the messages per subject with subjects_filter" do
    state = nc.jsm.stream_info("ORDERS", subjects_filter: ">").state
    expect(state.subjects).to eql("orders.eu.1" => 2, "orders.eu.2" => 1, "orders.us.1" => 3)

    state = nc.jsm.stream_info("ORDERS", subjects_filter: "orders.eu.*").state
    expect(state.subjects).to eql("orders.eu.1" => 2, "orders.eu.2" => 1)

    state = nc.jsm.stream_info("ORDERS", subjects_filter: "orders.us.1", deleted_details: true).state
    expect(state.subjects).to eql("orders.us.1" => 3)
    expect(state.deleted).to be_nil

    # Like nats.go, no matching subject gives an empty Hash.
    expect(nc.jsm.stream_info("ORDERS", subjects_filter: "orders.asia.>").state.subjects).to eql({})
  end

  it "requests every page of subjects" do
    # The server sends at most 100,000 subjects per response.
    nc.jsm.add_stream(name: "MANY", subjects: ["many.>"], storage: "memory")
    count = 100_010
    count.times { |i| nc.publish("many.#{i}") }
    nc.flush(30)
    # The stream stores what it was sent after the flush.
    deadline = Time.now + 30
    sleep 0.1 until nc.jsm.stream_info("MANY").state.messages == count || Time.now > deadline
    expect(nc.jsm.stream_info("MANY").state.messages).to eql(count)

    sent = []
    sub = nc.subscribe("$JS.API.STREAM.INFO.MANY") { |msg| sent << JSON.parse(msg.data) }
    nc.flush

    subjects = nc.jsm.stream_info("MANY", subjects_filter: "many.>", timeout: 30).state.subjects
    expect(subjects.size).to eql(count)
    expect(subjects["many.0"]).to eql(1)
    expect(subjects["many.100009"]).to eql(1)

    nc.flush
    sub.unsubscribe
    expect(sent).to eql([
      {"subjects_filter" => "many.>", "offset" => 0},
      {"subjects_filter" => "many.>", "offset" => 100_000}
    ])
  end

  it "keeps the timeout option" do
    expect { nc.jsm.stream_info("ORDERS", subjects_filter: ">", timeout: 2) }.not_to raise_error
    expect { nc.jsm.stream_info("MISSING", subjects_filter: ">") }.to raise_error(NATS::JetStream::Error::StreamNotFound)
  end

  it "decodes the lost data of a stream" do
    state = NATS::JetStream::API::StreamState.new(messages: 1, lost: {msgs: [3, 4], bytes: 120})
    expect(state.lost).to be_a(NATS::JetStream::API::LostStreamData)
    expect(state.lost.msgs).to eql([3, 4])
    expect(state.lost.bytes).to eql(120)
  end
end

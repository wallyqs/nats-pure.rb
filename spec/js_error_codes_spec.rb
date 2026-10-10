# frozen_string_literal: true

describe "JetStream API prefix and error codes" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-error-codes")
    @s = NatsServerControl.new("nats://127.0.0.1:4740", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  it "names the default API prefix, which a context uses unless given another" do
    expect(NATS::JetStream::DEFAULT_API_PREFIX).to eql("$JS.API")
    expect(js.prefix).to eql(NATS::JetStream::DEFAULT_API_PREFIX)
    expect(nc.jetstream(domain: "hub").prefix).to eql("$JS.hub.API")
    expect(nc.jetstream(prefix: "fromA").prefix).to eql("fromA")
  end

  it "names the err_codes that nats.go names, as in errors.json of nats-server" do
    codes = NATS::JetStream::ErrorCode
    expect(codes::BAD_REQUEST).to eql(10003)
    expect(codes::JETSTREAM_NOT_AVAILABLE).to eql(10008)
    expect(codes::CONSUMER_CREATE).to eql(10012)
    expect(codes::CONSUMER_NAME_EXISTS).to eql(10013)
    expect(codes::CONSUMER_NOT_FOUND).to eql(10014)
    expect(codes::INSUFFICIENT_RESOURCES).to eql(10023)
    expect(codes::MAXIMUM_CONSUMERS_LIMIT).to eql(10026)
    expect(codes::MESSAGE_NOT_FOUND).to eql(10037)
    expect(codes::JETSTREAM_NOT_ENABLED_FOR_ACCOUNT).to eql(10039)
    expect(codes::STREAM_NAME_IN_USE).to eql(10058)
    expect(codes::STREAM_NOT_FOUND).to eql(10059)
    expect(codes::STREAM_WRONG_LAST_SEQUENCE).to eql(10071)
    expect(codes::JETSTREAM_NOT_ENABLED).to eql(10076)
    expect(codes::CONSUMER_ALREADY_EXISTS).to eql(10105)
    expect(codes::DUPLICATE_FILTER_SUBJECTS).to eql(10136)
    expect(codes::OVERLAPPING_FILTER_SUBJECTS).to eql(10138)
    expect(codes::CONSUMER_EMPTY_FILTER).to eql(10139)
    expect(codes::CONSUMER_EXISTS).to eql(10148)
    expect(codes::CONSUMER_DOES_NOT_EXIST).to eql(10149)
    expect(codes::STREAM_WRONG_LAST_SEQUENCE_CONSTANT).to eql(10164)
    expect(codes::MIRROR_WITH_MSG_SCHEDULES).to eql(10186)
    expect(codes::SOURCE_WITH_MSG_SCHEDULES).to eql(10187)
    expect(codes::MESSAGE_SCHEDULES_DISABLED).to eql(10188)
    expect(codes::SCHEDULE_PATTERN_INVALID).to eql(10189)
    expect(codes::SCHEDULE_TARGET_INVALID).to eql(10190)
    expect(codes::SCHEDULE_TTL_INVALID).to eql(10191)
    expect(codes::SCHEDULE_ROLLUP_INVALID).to eql(10192)
    expect(codes::SCHEDULE_SOURCE_INVALID).to eql(10203)
    expect(codes::CONSUMER_INVALID_RESET).to eql(10204)
    expect(codes.constants.size).to eql(29)
  end

  it "matches the err_codes of the server's errors" do
    expect do
      js.consumer_info("NONE", "missing")
    end.to raise_error(NATS::JetStream::Error::APIError) { |e| expect(e.err_code).to eql(NATS::JetStream::ErrorCode::STREAM_NOT_FOUND) }

    js.add_stream(name: "CODES", subjects: ["codes.>"])
    expect do
      js.consumer_info("CODES", "missing")
    end.to raise_error(NATS::JetStream::Error::ConsumerNotFound) { |e| expect(e.err_code).to eql(NATS::JetStream::ErrorCode::CONSUMER_NOT_FOUND) }
  end

  describe "err_code 10003" do
    before { js.add_stream(name: "CODES", subjects: ["codes.>"]) }

    it "raises JSBadRequest, a BadRequest, for a request that the server takes as bad" do
      # A purge with both a sequence and a keep, which purge_stream refuses
      # itself, so it is sent by hand.
      req = {seq: 1, keep: 1}.to_json
      expect do
        js.send(:api_request, "#{js.prefix}.STREAM.PURGE.CODES", req)
      end.to raise_error(NATS::JetStream::Error::JSBadRequest) { |e|
        expect(e).to be_a(NATS::JetStream::Error::BadRequest)
        expect(e.code).to eql(400)
        expect(e.err_code).to eql(NATS::JetStream::ErrorCode::BAD_REQUEST)
        expect(e.description).to eql("bad request")
      }
      expect(NATS::JetStream::Error::JSBadRequest::ERR_CODE).to eql(10003)
    end

    it "raises JSBadRequest for an empty request where the server needs one" do
      expect do
        js.send(:api_request, "#{js.prefix}.STREAM.MSG.GET.CODES", "")
      end.to raise_error(NATS::JetStream::Error::JSBadRequest)
    end

    it "is not raised for other bad requests" do
      expect do
        js.publish("codes.a", "hi", stream: "OTHER")
      end.to raise_error(NATS::JetStream::Error::BadRequest) { |e| expect(e).not_to be_a(NATS::JetStream::Error::JSBadRequest) }
    end
  end
end

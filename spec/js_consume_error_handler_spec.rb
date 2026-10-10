# frozen_string_literal: true

describe "JetStream consume error handlers" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-consume-err")
    @s = NatsServerControl.new("nats://127.0.0.1:4768", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
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
    js.add_stream(name: "ERR", subjects: ["err.>"])
    js.add_consumer("ERR", durable_name: "pull", ack_policy: "none")
    js.add_consumer("ERR", durable_name: "push", deliver_subject: "deliver.push", filter_subject: "err.b", ack_policy: "none")
  end

  it "passes the context and the error to a handler of two arguments, like nats.go" do
    got = Queue.new
    handler = ->(ctx, err) { got << [ctx, err] }
    cc = js.consumer("ERR", "pull").consume(error_handler: handler) { |msg| raise "boom #{msg.data}" }
    js.publish("err.a", "0")

    ctx, err = got.pop(timeout: 5)
    expect(ctx).to equal(cc)
    expect(err.message).to eql("boom 0")
    cc.stop
  end

  it "lets the handler stop the consumption with the context" do
    cc = js.consumer("ERR", "pull").consume(error_handler: proc { |ctx, _err| ctx.stop }) do |msg|
      raise "stop on #{msg.data}"
    end
    js.publish("err.a", "0")
    expect(cc.wait_closed(5)).to be(true)
  end

  it "keeps passing only the error to a handler of one argument" do
    got = Queue.new
    [->(err) { got << err }, proc { |err| got << err }, ->(*args) { got << args }].each do |handler|
      cc = js.consumer("ERR", "pull").consume(error_handler: handler) { |msg| raise "one #{msg.data}" }
      js.publish("err.a", "x")
      value = got.pop(timeout: 5)
      value = value.first if value.is_a?(Array)
      expect(value).to be_a(RuntimeError)
      expect(value.message).to eql("one x")
      cc.stop
      cc.wait_closed(2)
    end
  end

  it "passes the context to the handlers of methods and callable objects" do
    got = Queue.new
    handler = Class.new do
      define_method(:call) { |ctx, err| got << [ctx, err] }
    end.new
    cc = js.consumer("ERR", "pull").consume(error_handler: handler) { |msg| raise "obj #{msg.data}" }
    js.publish("err.a", "0")
    ctx, err = got.pop(timeout: 5)
    expect(ctx).to equal(cc)
    expect(err.message).to eql("obj 0")
    cc.stop
    cc.wait_closed(2)

    receiver = Object.new
    receiver.define_singleton_method(:on_error) { |ctx, err| got << [ctx, err] }
    cc = js.consumer("ERR", "pull").consume(error_handler: receiver.method(:on_error)) { |msg| raise "meth #{msg.data}" }
    js.publish("err.a", "1")
    ctx, err = got.pop(timeout: 5)
    expect(ctx).to equal(cc)
    expect(err.message).to eql("meth 1")
    cc.stop
  end

  it "passes the context of ordered and push consumers" do
    got = Queue.new
    handler = ->(ctx, err) { got << [ctx, err] }
    cc = js.ordered_consumer("ERR").consume(error_handler: handler) { |msg| raise "ordered #{msg.data}" }
    js.publish("err.a", "0")
    ctx, err = got.pop(timeout: 5)
    expect(ctx).to equal(cc)
    expect(err.message).to eql("ordered 0")
    cc.stop

    cc = js.push_consumer("ERR", "push").consume(error_handler: handler) { |msg| raise "push #{msg.data}" }
    js.publish("err.b", "1")
    ctx, err = got.pop(timeout: 5)
    expect(ctx).to equal(cc)
    expect(err.message).to eql("push 1")
    cc.stop
  end
end

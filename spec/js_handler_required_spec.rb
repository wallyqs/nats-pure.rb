# frozen_string_literal: true

describe "JetStream consume without a handler" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-handler-required")
    @s = NatsServerControl.new("nats://127.0.0.1:4766", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  before { js.add_stream(name: "H", subjects: ["h.>"]) }

  def expect_handler_required
    expect { yield }.to raise_error(NATS::JetStream::Error::HandlerRequired, "nats: handler cannot be empty") do |err|
      # Still an ArgumentError, as raised before.
      expect(err).to be_a(ArgumentError)
    end
  end

  it "raises HandlerRequired from the consume of pull subscriptions and consumers" do
    psub = js.pull_subscribe("h.a", "pull")
    expect_handler_required { psub.consume }

    js.add_consumer("H", durable_name: "c")
    expect_handler_required { js.consumer("H", "c").consume }
    expect_handler_required { js.stream("H").create_consumer(durable_name: "d").consume(max_messages: 10) }
  end

  it "raises HandlerRequired from the consume of ordered consumers" do
    oc = js.ordered_consumer("H")
    expect_handler_required { oc.consume }
    # The consumer can still be consumed with a block.
    cc = oc.consume { |msg| msg }
    cc.stop
  end

  it "raises HandlerRequired from the consume of push consumers" do
    js.add_consumer("H", durable_name: "p", deliver_subject: "deliver.p")
    consumer = js.push_consumer("H", "p")
    expect_handler_required { consumer.consume }
    expect_handler_required { consumer.consume(error_handler: ->(err) { err }) }
    # Nothing was started: the handle can consume.
    cc = consumer.consume { |msg| msg }
    cc.stop
  end

  it "is an ArgumentError with a message of its own" do
    expect(NATS::JetStream::Error::HandlerRequired.new).to be_a(ArgumentError)
    expect(NATS::JetStream::Error::HandlerRequired.new("nats: other").message).to eql("nats: other")
  end
end

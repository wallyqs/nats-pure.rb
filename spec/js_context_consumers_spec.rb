# frozen_string_literal: true

describe "JetStream context consumer handles" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-context-consumers")
    @s = NatsServerControl.new("nats://127.0.0.1:4769", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }

  after { nc.close }

  before { js.add_stream(name: "CTX", subjects: ["ctx.>"]) }

  it "creates or updates a pull consumer, returning a Consumer, like CreateOrUpdateConsumer" do
    consumer = js.create_or_update_consumer("CTX", durable_name: "pull", ack_policy: "explicit")
    expect(consumer).to be_a(NATS::JetStream::Consumer)
    expect(consumer.stream).to eql("CTX")
    expect(consumer.name).to eql("pull")
    expect(consumer.cached_info.config.ack_policy).to eql("explicit")

    js.publish("ctx.a", "0")
    msg = consumer.next(timeout: 2)
    expect(msg.data).to eql("0")
    msg.ack_sync

    updated = js.create_or_update_consumer("CTX", NATS::JetStream::API::ConsumerConfig.new(durable_name: "pull", ack_policy: "explicit", description: "x"))
    expect(updated.cached_info.config.description).to eql("x")
    expect(js.consumer_info("CTX", "pull").config.description).to eql("x")
  end

  it "keeps create_consumer and update_consumer of the context returning ConsumerInfo" do
    info = js.create_consumer("CTX", durable_name: "c")
    expect(info).to be_a(NATS::JetStream::API::ConsumerInfo)
    expect(js.update_consumer("CTX", durable_name: "c", description: "y")).to be_a(NATS::JetStream::API::ConsumerInfo)
    expect(nc.jsm.add_consumer("CTX", durable_name: "c", description: "y")).to be_a(NATS::JetStream::API::ConsumerInfo)
  end

  it "creates a push consumer, returning a PushConsumer, like CreatePushConsumer" do
    consumer = js.create_push_consumer("CTX", durable_name: "push", deliver_subject: "deliver.push", ack_policy: "none")
    expect(consumer).to be_a(NATS::JetStream::PushConsumer)
    expect(consumer.stream).to eql("CTX")
    expect(consumer.name).to eql("push")
    expect(consumer.cached_info.config.deliver_subject).to eql("deliver.push")

    got = Queue.new
    cc = consumer.consume { |msg| got << msg.data }
    js.publish("ctx.a", "0")
    expect(got.pop(timeout: 2)).to eql("0")
    cc.stop

    # The same config again is fine; another one is not.
    expect(js.create_push_consumer("CTX", durable_name: "push", deliver_subject: "deliver.push", ack_policy: "none").name).to eql("push")
    expect do
      js.create_push_consumer("CTX", durable_name: "push", deliver_subject: "deliver.other", ack_policy: "none")
    end.to raise_error(NATS::JetStream::Error::ConsumerAlreadyExists)
  end

  it "updates a push consumer, returning a PushConsumer, like UpdatePushConsumer" do
    js.create_push_consumer("CTX", durable_name: "push", deliver_subject: "deliver.push")
    consumer = js.update_push_consumer("CTX", durable_name: "push", deliver_subject: "deliver.push", description: "z")
    expect(consumer).to be_a(NATS::JetStream::PushConsumer)
    expect(consumer.cached_info.config.description).to eql("z")

    expect do
      js.update_push_consumer("CTX", durable_name: "missing", deliver_subject: "deliver.missing")
    end.to raise_error(NATS::JetStream::Error::ConsumerDoesNotExist)
  end

  it "creates or updates a push consumer, returning a PushConsumer, like CreateOrUpdatePushConsumer" do
    consumer = js.create_or_update_push_consumer("CTX", durable_name: "push", deliver_subject: "deliver.push")
    expect(consumer).to be_a(NATS::JetStream::PushConsumer)
    consumer = js.create_or_update_push_consumer("CTX", durable_name: "push", deliver_subject: "deliver.push", description: "w")
    expect(consumer.cached_info.config.description).to eql("w")
    expect(js.push_consumer("CTX", "push").cached_info.config.description).to eql("w")
  end

  it "raises NotPushConsumer for a push consumer without a deliver subject, sending nothing" do
    %i[create_push_consumer update_push_consumer create_or_update_push_consumer].each do |method|
      expect { js.public_send(method, "CTX", durable_name: "pull") }.to raise_error(NATS::JetStream::Error::NotPushConsumer)
    end
    expect(js.consumer_names("CTX")).to be_empty
  end

  it "raises StreamNotFound for a stream that does not exist" do
    expect { js.create_or_update_consumer("MISSING", durable_name: "c") }.to raise_error(NATS::JetStream::Error::StreamNotFound)
    expect do
      js.create_push_consumer("MISSING", durable_name: "c", deliver_subject: "deliver.c")
    end.to raise_error(NATS::JetStream::Error::StreamNotFound)
  end
end

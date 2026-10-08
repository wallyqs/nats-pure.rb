# frozen_string_literal: true

describe "JetStream stream and consumer handles" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-js-handles")
    @s = NatsServerControl.new("nats://127.0.0.1:4743", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
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
    js.add_stream(name: "ORDERS", subjects: ["orders.>"])
    js.publish("orders.eu", "1")
    js.publish("orders.us", "2")
    js.publish("orders.eu", "3")
  end

  describe "Stream" do
    it "is got with its info" do
      stream = js.stream("ORDERS")
      expect(stream).to be_a(NATS::JetStream::Stream)
      expect(stream.name).to eql("ORDERS")
      expect(stream.cached_info).to be_a(NATS::JetStream::API::StreamInfo)
      expect(stream.cached_info.state.messages).to eql(3)
    end

    it "raises when the stream does not exist" do
      expect { js.stream("MISSING") }.to raise_error(NATS::JetStream::Error::StreamNotFound)
      expect { js.stream("") }.to raise_error(NATS::JetStream::Error::InvalidStreamName)
    end

    it "refreshes its info" do
      stream = js.stream("ORDERS")
      js.publish("orders.eu", "4")
      expect(stream.cached_info.state.messages).to eql(3)

      info = stream.info
      expect(info.state.messages).to eql(4)
      expect(stream.cached_info).to equal(info)
    end

    it "takes the stream info options, without caching the subjects" do
      stream = js.stream("ORDERS")
      stream.delete_msg(2)

      info = stream.info(subjects_filter: ">", deleted_details: true)
      expect(info.state.subjects).to eql("orders.eu" => 2)
      expect(info.state.deleted).to eql([2])
      expect(stream.cached_info.state.subjects).to be_nil
      expect(stream.cached_info.state.deleted).to eql([2])
      expect(stream.cached_info).to be_frozen
    end

    it "purges and deletes messages" do
      stream = js.stream("ORDERS")
      expect(stream.delete_msg(1)).to be(true)
      expect(stream.secure_delete_msg(2)).to be(true)
      expect { stream.delete_msg(2) }.to raise_error(NATS::JetStream::Error::APIError)
      expect(stream.info.state.messages).to eql(1)

      js.publish("orders.us", "4")
      expect(stream.purge(subject: "orders.eu").purged).to eql(1)
      expect(stream.purge.purged).to eql(1)
      expect(stream.info.state.messages).to eql(0)
    end

    it "gets messages" do
      stream = js.stream("ORDERS")
      msg = stream.get_msg(2)
      expect(msg.subject).to eql("orders.us")
      expect(msg.data).to eql("2")

      # The next message on the subject from the sequence on.
      msg = stream.get_msg(2, subject: "orders.eu")
      expect(msg.seq).to eql(3)
      expect(msg.data).to eql("3")

      msg = stream.get_last_msg_for_subject("orders.eu")
      expect(msg.data).to eql("3")

      expect { stream.get_msg(10) }.to raise_error(NATS::JetStream::Error::MsgNotFound)
      expect { stream.get_last_msg_for_subject("orders.asia") }.to raise_error(NATS::JetStream::Error::MsgNotFound)
    end

    it "gets messages directly when the stream allows it" do
      js.add_stream(name: "DIRECT", subjects: ["direct.>"], allow_direct: true)
      js.publish("direct.a", "x")
      js.publish("direct.b", "y")
      stream = js.stream("DIRECT")

      sent = []
      sub = nc.subscribe("$JS.API.>") { |msg| sent << msg.subject }
      nc.flush

      expect(stream.get_msg(1).data).to eql("x")
      expect(stream.get_last_msg_for_subject("direct.b").data).to eql("y")
      expect(js.stream("ORDERS").get_msg(1).data).to eql("1")
      nc.flush
      sub.unsubscribe

      expect(sent).to eql([
        "$JS.API.DIRECT.GET.DIRECT",
        "$JS.API.DIRECT.GET.DIRECT.direct.b",
        "$JS.API.STREAM.INFO.ORDERS",
        "$JS.API.STREAM.MSG.GET.ORDERS"
      ])
    end

    it "creates, updates, gets, lists and deletes consumers" do
      stream = js.stream("ORDERS")
      consumer = stream.create_consumer(durable_name: "dur", filter_subject: "orders.eu")
      expect(consumer).to be_a(NATS::JetStream::Consumer)
      expect(consumer.name).to eql("dur")
      expect(consumer.stream).to eql("ORDERS")
      expect(consumer.cached_info.num_pending).to eql(2)

      expect do
        stream.create_consumer(durable_name: "dur", filter_subject: "orders.us")
      end.to raise_error(NATS::JetStream::Error::ConsumerAlreadyExists)

      updated = stream.update_consumer(durable_name: "dur", filter_subject: "orders.eu", description: "eu")
      expect(updated.cached_info.config.description).to eql("eu")
      expect do
        stream.update_consumer(durable_name: "missing")
      end.to raise_error(NATS::JetStream::Error::ConsumerDoesNotExist)

      other = stream.create_or_update_consumer(name: "other")
      expect(other.name).to eql("other")
      expect(stream.create_or_update_consumer(name: "other", description: "x").cached_info.config.description).to eql("x")

      expect(stream.consumer("dur").cached_info.config.description).to eql("eu")
      expect(stream.consumer_names).to eql(["dur", "other"])
      expect(stream.consumers.map(&:name)).to eql(["dur", "other"])
      expect(stream.list_consumers.map(&:name)).to eql(["dur", "other"])

      expect(stream.delete_consumer("other")).to be(true)
      expect { stream.consumer("other") }.to raise_error(NATS::JetStream::Error::ConsumerNotFound)
      expect(stream.consumer_names).to eql(["dur"])
    end

    it "pauses, resumes and resets consumers" do
      stream = js.stream("ORDERS")
      stream.create_consumer(durable_name: "dur")
      resp = stream.pause_consumer("dur", Time.now + 60)
      expect(resp.paused).to be(true)
      expect(stream.resume_consumer("dur").paused).to be(false)

      consumer = stream.consumer("dur")
      consumer.fetch(3)
      expect(stream.reset_consumer("dur").reset_seq).to eql(1)
    end

    it "reads in order" do
      oc = js.stream("ORDERS").ordered_consumer
      expect(oc.fetch(3).map(&:data)).to eql(["1", "2", "3"])
    end
  end

  describe "Consumer" do
    it "is got with its info" do
      js.add_consumer("ORDERS", durable_name: "dur")
      consumer = js.consumer("ORDERS", "dur")
      expect(consumer).to be_a(NATS::JetStream::Consumer)
      expect(consumer.name).to eql("dur")
      expect(consumer.cached_info.num_pending).to eql(3)

      expect { js.consumer("ORDERS", "missing") }.to raise_error(NATS::JetStream::Error::ConsumerNotFound)
      expect { js.consumer("MISSING", "dur") }.to raise_error(NATS::JetStream::Error::StreamNotFound)
    end

    it "is not a push consumer" do
      js.add_consumer("ORDERS", durable_name: "push", deliver_subject: "deliver")
      expect { js.consumer("ORDERS", "push") }.to raise_error(NATS::JetStream::Error::NotPullConsumer)
    end

    it "refreshes its info" do
      consumer = js.stream("ORDERS").create_consumer(durable_name: "dur")
      consumer.fetch(2).each(&:ack_sync)
      expect(consumer.cached_info.num_pending).to eql(3)

      info = consumer.info
      expect(info.num_pending).to eql(1)
      expect(info.ack_floor.stream_seq).to eql(2)
      expect(consumer.cached_info).to equal(info)
    end

    it "fetches messages" do
      consumer = js.stream("ORDERS").create_consumer(durable_name: "dur")
      msgs = consumer.fetch(2)
      expect(msgs.map(&:data)).to eql(["1", "2"])
      msgs.each(&:ack)

      msg = consumer.next(timeout: 1)
      expect(msg.data).to eql("3")
      msg.ack

      expect { consumer.next(timeout: 0.5) }.to raise_error(NATS::Timeout)
      expect(consumer.fetch_no_wait(10)).to eql([])

      js.publish("orders.eu", "4")
      js.publish("orders.eu", "5")
      expect(consumer.fetch_no_wait(10).map(&:data)).to eql(["4", "5"])
    end

    it "fetches messages by bytes" do
      consumer = js.stream("ORDERS").create_consumer(durable_name: "dur")
      # Each message is some 70 bytes, as the server counts them.
      msgs = consumer.fetch_bytes(150, timeout: 1)
      expect(msgs.map(&:data)).to eql(["1", "2"])
    end

    it "consumes messages" do
      consumer = js.stream("ORDERS").create_consumer(durable_name: "dur")
      got = Queue.new
      cc = consumer.consume { |msg| got << msg.data }
      expect(3.times.map { got.pop(timeout: 5) }).to eql(["1", "2", "3"])
      cc.stop

      msgs = consumer.messages
      js.publish("orders.eu", "4")
      expect(msgs.next(timeout: 5).data).to eql("4")
      msgs.stop
    end
  end

  describe "PushConsumer" do
    it "is created and got with its info" do
      stream = js.stream("ORDERS")
      consumer = stream.create_push_consumer(durable_name: "push", deliver_subject: "deliver.push")
      expect(consumer).to be_a(NATS::JetStream::PushConsumer)
      expect(consumer.name).to eql("push")
      expect(consumer.stream).to eql("ORDERS")
      expect(consumer.cached_info.config.deliver_subject).to eql("deliver.push")

      updated = stream.update_push_consumer(durable_name: "push", deliver_subject: "deliver.push", description: "d")
      expect(updated.cached_info.config.description).to eql("d")
      upserted = stream.create_or_update_push_consumer(durable_name: "push2", deliver_subject: "deliver.push2")
      expect(upserted.name).to eql("push2")

      got = js.push_consumer("ORDERS", "push")
      expect(got.cached_info.config.description).to eql("d")
      expect(got.info.num_pending).to eql(3)
      expect(stream.push_consumer("push2").name).to eql("push2")
    end

    it "needs a deliver subject" do
      stream = js.stream("ORDERS")
      expect { stream.create_push_consumer(durable_name: "pull") }.to raise_error(NATS::JetStream::Error::NotPushConsumer)
      expect { stream.create_or_update_push_consumer(NATS::JetStream::API::ConsumerConfig.new(durable_name: "pull")) }
        .to raise_error(NATS::JetStream::Error::NotPushConsumer)

      stream.create_consumer(durable_name: "pull")
      expect { js.push_consumer("ORDERS", "pull") }.to raise_error(NATS::JetStream::Error::NotPushConsumer)
    end
  end
end

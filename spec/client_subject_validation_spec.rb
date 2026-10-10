# frozen_string_literal: true

describe "Client - subject validation" do
  before(:all) do
    @s = NatsServerControl.new("nats://127.0.0.1:4927", "/tmp/test-nats.pid")
    @s.start_server(true)
  end

  after(:all) do
    @s.kill_server
  end

  let(:errors) { Queue.new }

  def connect(**opts)
    nc = NATS::IO::Client.new
    nc.on_error { |e| errors << e }
    nc.connect("nats://127.0.0.1:4927", reconnect: false, **opts)
  end

  context "by default" do
    let(:nc) { connect }

    after { nc.close }

    it "refuses subscriptions that are empty, have whitespace or empty tokens, like nats.go" do
      ["", "foo bar", "foo\tbar", "foo\r\n", "foo.", ".foo", "foo..bar", "."].each do |subject|
        expect { nc.subscribe(subject) }.to raise_error(NATS::IO::BadSubject, "nats: invalid subject"), subject.inspect
      end
      %w[foo foo.bar foo.* foo.> * >].each { |subject| nc.subscribe(subject) }
      nc.flush
      expect(nc).to be_connected
      expect(errors).to be_empty
    end

    it "refuses to publish or request to subjects that are empty or have whitespace, like nats.go" do
      ["", "foo bar", "foo\tbar", "foo\r\n"].each do |subject|
        expect { nc.publish(subject, "hi") }.to raise_error(NATS::IO::BadSubject, "nats: invalid subject"), subject.inspect
        expect { nc.publish_msg(NATS::Msg.new(subject: subject)) }.to raise_error(NATS::IO::BadSubject)
        expect { nc.request(subject, "hi", timeout: 0.1) }.to raise_error(NATS::IO::BadSubject)
        expect { nc.request_msg(NATS::Msg.new(subject: subject), timeout: 0.1) }.to raise_error(NATS::IO::BadSubject)
      end
      expect { nc.publish(nil) }.to raise_error(NATS::IO::BadSubject)
      nc.flush
      expect(nc).to be_connected
    end

    it "refuses reply subjects with whitespace" do
      expect { nc.publish("foo", "hi", "bad reply") }.to raise_error(NATS::IO::BadSubject)
      expect { nc.publish_msg(NATS::Msg.new(subject: "foo", reply: "bad\nreply")) }.to raise_error(NATS::IO::BadSubject)
    end

    it "publishes to subjects that nats.go publishes to" do
      sub = nc.subscribe(">")
      nc.flush
      %w[foo foo.bar foo..bar foo.].each { |subject| nc.publish(subject, subject) }
      nc.flush
      expect(Array.new(2) { sub.next_msg.subject }).to eq(%w[foo foo.bar])
      expect(nc).to be_connected
    end
  end

  context "with skip_subject_validation" do
    let(:nc) { connect(skip_subject_validation: true) }

    after { nc.close if nc.connected? }

    it "leaves the empty tokens of subscriptions to the server, which refuses them" do
      nc.subscribe("foo.")
      expect(errors.pop(timeout: 2)).to be_a(NATS::IO::ServerError)
    end

    it "still refuses empty subjects, and whitespace in subscriptions" do
      expect { nc.publish("") }.to raise_error(NATS::IO::BadSubject)
      expect { nc.subscribe("foo bar") }.to raise_error(NATS::IO::BadSubject)
    end

    it "does not check the subjects of publishes, like nats.go" do
      sub = nc.subscribe("foo")
      nc.flush
      # The server reads the whitespace as the end of the subject.
      nc.publish("foo bar", "hi")
      msg = sub.next_msg
      expect([msg.subject, msg.reply, msg.data]).to eq(%w[foo bar hi])
    end
  end
end

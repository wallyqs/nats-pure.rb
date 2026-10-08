# frozen_string_literal: true

describe "KeyValue through a JetStream API prefix" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-kv-api-prefix")
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  # The next update of a watcher that is not the end of its initial values.
  def next_update(watcher)
    loop do
      entry = watcher.updates(timeout: 2)
      return entry unless entry.nil?
    end
  end

  describe "imported from another account" do
    # Like TestKeyValueCrossAccounts of nats.go: account I imports the
    # JetStream API and the subjects of the buckets of account A under
    # the prefix fromA, and the deliveries to its inboxes.
    before do
      @s = NatsServerControl.init_with_config_from_string(%(
        port = 4630
        jetstream { store_dir = "#{@tmpdir}" }
        accounts {
          A {
            jetstream = enabled
            users = [{user = "a", password = "a"}]
            exports = [
              {service = "$JS.API.>"}
              {service = "$KV.>"}
              {stream = "accI.>"}
            ]
          }
          I {
            users = [{user = "i", password = "i"}]
            imports = [
              {service = {account = A, subject = "$JS.API.>"}, to = "fromA.>"}
              {service = {account = A, subject = "$KV.>"}, to = "fromA.$KV.>"}
              {stream = {account = A, subject = "accI.>"}}
            ]
          }
        }
      ), {"pid_file" => "/tmp/test-nats.pid", "host" => "127.0.0.1", "port" => 4630})
      @s.start_server(true)
    end

    let(:nc1) { NATS.connect("nats://a:a@127.0.0.1:4630") }
    let(:nc2) { NATS.connect("nats://i:i@127.0.0.1:4630", custom_inbox_prefix: "accI") }
    let(:js1) { nc1.jetstream }
    let(:js2) { nc2.jetstream(prefix: "fromA") }

    after do
      nc1.close
      nc2.close
    end

    it "puts, updates, deletes and purges the keys of the bucket of the other account" do
      kv1 = js1.create_key_value(bucket: "Map", history: 10)
      kv2 = js2.create_key_value(bucket: "Map", history: 10)
      w1 = kv1.watch("map")
      w2 = kv2.watch("map")

      rev = kv2.put("map", "value")
      expect(kv1.get("map").value).to eql("value")
      expect(kv2.get("map").value).to eql("value")
      expect(next_update(w1).value).to eql("value")
      expect(next_update(w2).value).to eql("value")

      kv2.update("map", "updated", last: rev)
      expect(kv1.get("map").value).to eql("updated")
      expect(kv2.get("map").value).to eql("updated")
      expect(next_update(w1).value).to eql("updated")
      expect(next_update(w2).value).to eql("updated")

      expect(kv2.create("other", "1")).to eql(rev + 2)
      expect { kv2.create("other", "2") }.to raise_error(NATS::KeyValue::KeyExistsError)
      expect { kv2.delete("other", last: rev) }.to raise_error(NATS::KeyValue::KeyRevisionMismatchError)

      kv2.purge("map")
      expect(next_update(w1).operation).to eql("PURGE")
      expect(next_update(w2).operation).to eql("PURGE")

      kv2.purge_deletes(older_than: -1)
      kv2.delete("other")
      expect { kv1.get("other") }.to raise_error(NATS::KeyValue::KeyNotFoundError)
      expect { kv1.get("map") }.to raise_error(NATS::KeyValue::KeyNotFoundError)
      w1.stop
      w2.stop
    end
  end

  describe "of a domain" do
    before do
      @s = NatsServerControl.init_with_config_from_string(%(
        port = 4631
        jetstream { store_dir = "#{@tmpdir}", domain = "hub" }
      ), {"pid_file" => "/tmp/test-nats.pid", "host" => "127.0.0.1", "port" => 4631})
      @s.start_server(true)
    end

    let(:nc) { NATS.connect("nats://127.0.0.1:4631") }

    after { nc.close }

    it "writes through the API of the domain, which the server maps to the bucket" do
      js = nc.jetstream(domain: "hub")
      kv = js.create_key_value(bucket: "D", history: 5)
      allow(js).to receive(:publish).and_call_original

      rev = kv.put("a", "1")
      expect(kv.update("a", "2", last: rev)).to eql(rev + 1)
      kv.delete("a")
      kv.purge("b")
      expect(js).to have_received(:publish).with("$JS.hub.API.$KV.D.a", any_args).exactly(3).times
      expect(js).to have_received(:publish).with("$JS.hub.API.$KV.D.b", any_args).once
      expect(nc.jetstream.key_value("D").history("a").map(&:operation)).to eql(%w[PUT PUT DEL])
    end

    it "writes to the subjects of the bucket without a domain" do
      js = nc.jetstream
      kv = js.create_key_value(bucket: "D")
      allow(js).to receive(:publish).and_call_original

      kv.put("a", "1")
      expect(js).to have_received(:publish).with("$KV.D.a", "1")
    end
  end
end

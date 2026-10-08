# frozen_string_literal: true

describe "ObjectStore" do
  before do
    @tmpdir = Dir.mktmpdir("ruby-object-store")
    @s = NatsServerControl.new("nats://127.0.0.1:4627", "/tmp/test-nats.pid", "-js -sd=#{@tmpdir}")
    @s.start_server(true)
  end

  after do
    @s.kill_server
    FileUtils.remove_entry(@tmpdir)
  end

  let(:nc) { NATS.connect(@s.uri) }
  let(:js) { nc.jetstream }
  let(:obs) { js.create_object_store(bucket: "OBJS", description: "objects") }

  after { nc.close }

  def random_data(size)
    Random.new(size).bytes(size)
  end

  describe "manager" do
    it "creates an object store on the stream OBJ_<bucket>" do
      obs
      config = js.stream_info("OBJ_OBJS").config
      expect(config.subjects).to eql(["$O.OBJS.C.>", "$O.OBJS.M.>"])
      expect(config.description).to eql("objects")
      expect(config.discard).to eql("new")
      expect(config.allow_rollup_hdrs).to eql(true)
      expect(config.allow_direct).to eql(true)
      expect(obs.bucket).to eql("OBJS")
    end

    it "takes a name, a Hash or an ObjectStoreConfig" do
      expect(js.create_object_store("ONE").bucket).to eql("ONE")
      config = NATS::ObjectStore::API::ObjectStoreConfig.new(bucket: "TWO", ttl: 60, storage: "memory", metadata: {"a" => "b"})
      store = js.create_object_store(config)
      status = store.status
      expect(status.ttl).to eql(60)
      expect(status.storage).to eql("memory")
      expect(status.metadata).to include(a: "b")
    end

    it "refuses invalid names" do
      expect { js.create_object_store("no.dots") }.to raise_error(NATS::ObjectStore::InvalidStoreNameError, "nats: invalid object-store name")
      expect { js.object_store("") }.to raise_error(NATS::ObjectStore::InvalidStoreNameError)
      expect { js.delete_object_store("a b") }.to raise_error(NATS::ObjectStore::InvalidStoreNameError)
      expect { js.create_object_store(nil) }.to raise_error(NATS::ObjectStore::ObjectConfigRequiredError)
    end

    it "raises BucketExistsError for an object store with another config" do
      js.create_object_store(bucket: "EXISTS")
      expect(js.create_object_store(bucket: "EXISTS").bucket).to eql("EXISTS")
      expect do
        js.create_object_store(bucket: "EXISTS", description: "other")
      end.to raise_error(NATS::ObjectStore::BucketExistsError, /bucket name already in use/)
    end

    it "binds to an existing object store" do
      obs.put_string("a", "1")
      expect(js.object_store("OBJS").get_string("a")).to eql("1")
      expect { js.object_store("MISSING") }.to raise_error(NATS::ObjectStore::BucketNotFoundError)
    end

    it "updates and creates or updates object stores" do
      obs
      expect(js.update_object_store(bucket: "OBJS", description: "updated").status.description).to eql("updated")
      expect { js.update_object_store(bucket: "MISSING") }.to raise_error(NATS::ObjectStore::BucketNotFoundError)
      expect(js.create_or_update_object_store(bucket: "NEW", description: "new").status.description).to eql("new")
      expect(js.create_or_update_object_store(bucket: "NEW", description: "newer").status.description).to eql("newer")
    end

    it "deletes object stores" do
      obs
      expect(js.delete_object_store("OBJS")).to eql(true)
      expect { js.object_store("OBJS") }.to raise_error(NATS::ObjectStore::BucketNotFoundError)
      expect { js.delete_object_store("OBJS") }.to raise_error(NATS::ObjectStore::BucketNotFoundError)
    end

    it "lists object stores" do
      expect(js.object_store_names).to eql([])
      js.create_object_store("ONE")
      js.create_object_store("TWO")
      js.create_key_value(bucket: "KV")
      js.add_stream(name: "OBJ_FAKE", subjects: ["fake"])

      expect(js.object_store_names).to match_array(["ONE", "TWO"])
      statuses = js.object_stores
      expect(statuses).to all(be_a(NATS::ObjectStore::BucketStatus))
      expect(statuses.map(&:bucket)).to match_array(["ONE", "TWO"])
      expect(js.key_value_store_names).to eql(["KV"])
    end
  end

  describe "put and get" do
    it "stores a String and reads it back" do
      info = obs.put_string("hello", "world")
      expect(info.name).to eql("hello")
      expect(info.bucket).to eql("OBJS")
      expect(info.size).to eql(5)
      expect(info.chunks).to eql(1)
      expect(info.digest).to eql("SHA-256=#{Base64.urlsafe_encode64(Digest::SHA256.digest("world"))}")
      expect(info.nuid).not_to be_empty

      result = obs.get("hello")
      expect(result.data).to eql("world".b)
      expect(result.info.digest).to eql(info.digest)
      expect(result.info.mtime).to be_a(Time)
      expect(obs.get_string("hello")).to eql("world")
      expect(obs.get_string("hello").encoding).to eql(Encoding::UTF_8)
      expect(obs.get_bytes("hello").encoding).to eql(Encoding::BINARY)
    end

    it "stores the data in chunks on $O.<bucket>.C.<nuid> and its meta on $O.<bucket>.M.<name>" do
      data = random_data(300_000)
      info = obs.put("blob", data)
      expect(info.chunks).to eql(3)
      expect(info.options.max_chunk_size).to eql(128 * 1024)

      chunk = js.get_msg("OBJ_OBJS", seq: 1)
      expect(chunk.subject).to eql("$O.OBJS.C.#{info.nuid}")
      expect(chunk.data.bytesize).to eql(128 * 1024)

      meta = js.get_last_msg("OBJ_OBJS", "$O.OBJS.M.#{Base64.urlsafe_encode64("blob")}")
      expect(meta.headers["Nats-Rollup"]).to eql("sub")
      json = JSON.parse(meta.data)
      expect(json).to include(
        "name" => "blob", "bucket" => "OBJS", "nuid" => info.nuid, "size" => 300_000,
        "chunks" => 3, "digest" => info.digest, "mtime" => "0001-01-01T00:00:00Z",
        "options" => {"max_chunk_size" => 131072}
      )

      expect(obs.get("blob").data).to eql(data)
    end

    it "reads data from an IO, in chunks of the given size" do
      data = random_data(25_000)
      info = obs.put({name: "io", description: "from an IO", headers: {"X-A" => "1", "X-B" => ["2", "3"]},
                      metadata: {"k" => "v"}, options: {max_chunk_size: 10_000}}, StringIO.new(data))
      expect(info.chunks).to eql(3)
      expect(info.headers).to eql({"X-A" => ["1"], "X-B" => ["2", "3"]})

      fetched = obs.get_info("io")
      expect(fetched.description).to eql("from an IO")
      expect(fetched.headers).to eql({"X-A" => ["1"], "X-B" => ["2", "3"]})
      expect(fetched.metadata).to eql({"k" => "v"})
      expect(fetched.options.max_chunk_size).to eql(10_000)
      expect(obs.get_bytes("io")).to eql(data)
    end

    it "writes the data to an IO" do
      data = random_data(200_000)
      obs.put("io", data)
      io = StringIO.new("".b)
      result = obs.get("io", io: io)
      expect(result.data).to be_nil
      expect(result.info.size).to eql(200_000)
      expect(io.string).to eql(data)
    end

    it "stores empty objects" do
      info = obs.put("empty")
      expect(info.size).to eql(0)
      expect(info.chunks).to eql(0)
      expect(info.digest).to eql(NATS::ObjectStore.digest_value(""))
      expect(obs.get("empty").data).to eql("".b)
    end

    it "puts and gets files" do
      path = File.join(@tmpdir, "in.bin")
      out = File.join(@tmpdir, "out.bin")
      data = random_data(150_000)
      File.binwrite(path, data)

      info = obs.put_file(path)
      expect(info.name).to eql(path)
      obs.put_file(path, name: "named")
      expect(obs.get_file("named", out).size).to eql(150_000)
      expect(File.binread(out)).to eql(data)

      expect { obs.get_file("missing", out) }.to raise_error(NATS::ObjectStore::ObjectNotFoundError)
      expect(File.exist?(out)).to eql(false)
    end

    it "replaces an object, removing its earlier chunks" do
      first = obs.put("obj", random_data(300_000))
      second = obs.put("obj", "small")
      expect(second.nuid).not_to eql(first.nuid)
      expect(obs.get_string("obj")).to eql("small")
      # The chunk and meta of the second put.
      expect(js.stream_info("OBJ_OBJS").state.messages).to eql(2)
    end

    it "raises ObjectNotFoundError for objects that do not exist" do
      expect { obs.get("missing") }.to raise_error(NATS::ObjectStore::ObjectNotFoundError, "nats: object not found")
      expect { obs.get_info("missing") }.to raise_error(NATS::ObjectStore::ObjectNotFoundError)
    end

    it "refuses objects without a name, and links" do
      expect { obs.put({name: ""}, "x") }.to raise_error(NATS::ObjectStore::BadObjectMetaError)
      expect { obs.get_info("") }.to raise_error(NATS::ObjectStore::NameRequiredError)
      link = {bucket: "OBJS", name: "x"}
      expect do
        obs.put({name: "link", options: {link: link}}, "x")
      end.to raise_error(NATS::ObjectStore::LinkNotAllowedError)
    end

    it "raises DigestMismatchError when the data does not match its digest" do
      info = obs.put("obj", "data")
      info.digest = NATS::ObjectStore.digest_value("other")
      js.publish("$O.OBJS.M.#{Base64.urlsafe_encode64("obj")}", info.to_json, header: {"Nats-Rollup" => "sub"})
      expect { obs.get("obj") }.to raise_error(NATS::ObjectStore::DigestMismatchError)
    end

    it "raises BadObjectMetaError for meta information that is not JSON" do
      obs
      js.publish("$O.OBJS.M.#{Base64.urlsafe_encode64("bad")}", "{not json")
      expect { obs.get_info("bad") }.to raise_error(NATS::ObjectStore::BadObjectMetaError)
    end

    it "works on streams without direct gets" do
      js.add_stream(name: "OBJ_NODIRECT", subjects: ["$O.NODIRECT.C.>", "$O.NODIRECT.M.>"],
        allow_rollup_hdrs: true, discard: "new")
      store = js.object_store("NODIRECT")
      data = random_data(300_000)
      store.put("obj", data)
      result = store.get("obj")
      expect(result.data).to eql(data)
      expect(result.info.mtime).to be_within(60).of(Time.now)
    end
  end

  describe "digests" do
    it "formats and decodes digests like nats.go" do
      digest = NATS::ObjectStore.digest_value("hello")
      expect(digest).to eql("SHA-256=LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=")
      expect(NATS::ObjectStore.decode_digest(digest)).to eql(Digest::SHA256.digest("hello"))
      expect { NATS::ObjectStore.decode_digest("nodigest") }.to raise_error(NATS::ObjectStore::InvalidDigestFormatError)
    end
  end

  describe "update_meta" do
    it "changes the information about an object" do
      obs.put({name: "obj", options: {max_chunk_size: 2}}, "data")
      obs.update_meta("obj", name: "obj", description: "described", metadata: {"a" => "1"})
      info = obs.get_info("obj")
      expect(info.description).to eql("described")
      expect(info.metadata).to eql({"a" => "1"})
      expect(info.options.max_chunk_size).to eql(2)
      expect(obs.get_string("obj")).to eql("data")
    end

    it "renames an object" do
      obs.put("old", "data")
      obs.update_meta("old", name: "new")
      expect(obs.get_string("new")).to eql("data")
      expect { obs.get_info("old", show_deleted: true) }.to raise_error(NATS::ObjectStore::ObjectNotFoundError)
    end

    it "refuses to rename onto another object, or to update a missing one" do
      obs.put("a", "1")
      obs.put("b", "2")
      expect { obs.update_meta("a", name: "b") }.to raise_error(NATS::ObjectStore::ObjectAlreadyExistsError)
      expect { obs.update_meta("missing", name: "c") }.to raise_error(NATS::ObjectStore::UpdateMetaDeletedError)

      obs.delete("b")
      obs.update_meta("a", name: "b")
      expect(obs.get_string("b")).to eql("1")
    end
  end

  describe "delete" do
    it "marks the object as deleted and removes its chunks" do
      obs.put("obj", random_data(300_000))
      expect(obs.delete("obj")).to eql(true)

      expect { obs.get("obj") }.to raise_error(NATS::ObjectStore::ObjectNotFoundError)
      info = obs.get_info("obj", show_deleted: true)
      expect(info.deleted).to eql(true)
      expect(info.size).to eql(0)
      expect(info.chunks).to eql(0)
      expect(info.digest).to be_nil
      expect(js.stream_info("OBJ_OBJS").state.messages).to eql(1)
      expect(obs.get("obj", show_deleted: true).data).to eql("".b)

      expect(obs.delete("obj")).to eql(true)
      expect { obs.delete("missing") }.to raise_error(NATS::ObjectStore::ObjectNotFoundError)
    end
  end

  describe "links" do
    it "links to objects of the same and other object stores" do
      obs.put("target", "data")
      link = obs.add_link("link", obs.get_info("target"))
      expect(link.link?).to eql(true)
      expect(link.options.link.to_h).to eql({bucket: "OBJS", name: "target"})
      expect(obs.get_string("link")).to eql("data")

      other = js.create_object_store("OTHER")
      other.put("remote", "remote data")
      obs.add_link("remote-link", other.get_info("remote"))
      expect(obs.get_string("remote-link")).to eql("remote data")
    end

    it "links to object stores, which get cannot read" do
      other = js.create_object_store("OTHER")
      link = obs.add_bucket_link("bucket", other)
      expect(link.options.link.bucket).to eql("OTHER")
      expect(link.options.link.name).to be_nil
      expect { obs.get("bucket") }.to raise_error(NATS::ObjectStore::CantGetBucketError)
    end

    it "refuses invalid links" do
      target = obs.put("target", "data")
      link = obs.add_link("link", target)
      obs.put("object", "data")

      expect { obs.add_link("", target) }.to raise_error(NATS::ObjectStore::NameRequiredError)
      expect { obs.add_link("x", nil) }.to raise_error(NATS::ObjectStore::ObjectRequiredError)
      expect { obs.add_link("x", link) }.to raise_error(NATS::ObjectStore::NoLinkToLinkError)
      expect { obs.add_link("object", target) }.to raise_error(NATS::ObjectStore::ObjectAlreadyExistsError)
      expect { obs.add_bucket_link("x", nil) }.to raise_error(NATS::ObjectStore::BucketRequiredError)
      expect { obs.add_bucket_link("x", "OBJS") }.to raise_error(NATS::ObjectStore::BucketMalformedError)

      obs.delete("target")
      expect do
        obs.add_link("x", obs.get_info("target", show_deleted: true))
      end.to raise_error(NATS::ObjectStore::NoLinkToDeletedError)

      # A link can replace a link.
      other = obs.put("other", "other")
      obs.add_link("link", other)
      expect(obs.get_string("link")).to eql("other")
    end
  end

  describe "seal" do
    it "seals the object store" do
      obs.put("obj", "data")
      expect(obs.seal).to eql(true)
      expect(obs.status.sealed?).to eql(true)
      expect(obs.get_string("obj")).to eql("data")
      expect { obs.put("other", "data") }.to raise_error(NATS::JetStream::Error::APIError)
    end
  end

  describe "watch and list" do
    it "watches the objects that change" do
      obs.put("a", "1")
      obs.put("b", "2")
      obs.put("a", "3")

      w = obs.watch
      initial = [w.updates, w.updates]
      expect(initial.map(&:name)).to eql(["b", "a"])
      expect(initial.last.size).to eql(1)
      expect(initial.last.mtime).to be_a(Time)
      expect(w.updates).to be_nil

      obs.put("c", "4")
      expect(w.updates.name).to eql("c")
      obs.delete("b")
      deleted = w.updates
      expect([deleted.name, deleted.deleted?]).to eql(["b", true])
      w.stop
    end

    it "takes watch options" do
      obs.put("a", "1")
      obs.put("a", "22")
      obs.put("b", "2")
      obs.delete("b")

      # Each meta information rolls up the earlier one of the object, so
      # the history holds only the latest.
      w = obs.watch(include_history: true)
      expect(w.take(3).map { |info| info && [info.name, info.size] }).to eql([["a", 2], ["b", 0], nil])
      w.stop

      w = obs.watch(ignore_deletes: true)
      expect(w.updates.name).to eql("a")
      expect(w.updates).to be_nil
      w.stop

      w = obs.watch(updates_only: true)
      obs.put("c", "3")
      expect(w.updates.name).to eql("c")
      w.stop
    end

    it "sends nil at once when the object store is empty" do
      w = obs.watch
      expect(w.updates).to be_nil
      w.stop
    end

    it "lists the objects" do
      expect { obs.list }.to raise_error(NATS::ObjectStore::NoObjectsFoundError, "nats: no objects found")
      obs.put("a", "1")
      obs.put("b", "2")
      obs.delete("b")
      expect(obs.list.map(&:name)).to eql(["a"])
      expect(obs.list(show_deleted: true).map(&:name)).to eql(["a", "b"])
    end
  end

  describe "status" do
    it "reports the status of the object store" do
      obs.put("a", "data")
      status = obs.status
      expect(status.bucket).to eql("OBJS")
      expect(status.description).to eql("objects")
      expect(status.ttl).to eql(0)
      expect(status.storage).to eql("file")
      expect(status.replicas).to eql(1)
      expect(status.sealed?).to eql(false)
      expect(status.size).to be > 0
      expect(status.backing_store).to eql("JetStream")
      expect(status.compressed?).to eql(false)
      expect(status.stream_info.config.name).to eql("OBJ_OBJS")
    end
  end
end

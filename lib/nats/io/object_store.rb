# frozen_string_literal: true

# Copyright 2026 The NATS Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require "base64"
require "digest"
require "stringio"
require "time"
require_relative "object_store/api"
require_relative "object_store/bucket_status"
require_relative "object_store/errors"
require_relative "object_store/manager"

module NATS
  # ObjectStore stores objects of any size in a JetStream stream, split into
  # chunks, in the same format as nats.go and the other NATS clients: the
  # stream OBJ_<bucket> keeps the chunks of each object on
  # $O.<bucket>.C.<nuid>, and its meta information, as JSON, on
  # $O.<bucket>.M.<base64url of its name>.
  #
  # @example
  #   js = nc.jetstream
  #   obs = js.create_object_store("files")
  #   obs.put("hello.txt", "Hello World!")
  #   obs.get("hello.txt").data # => "Hello World!"
  class ObjectStore
    VALID_BUCKET_RE = /\A[a-zA-Z0-9_-]+\z/
    # Size of the chunks of objects unless their options set one.
    DEFAULT_CHUNK_SIZE = 128 * 1024
    DIGEST_TYPE = "SHA-256="
    ROLLUP = "Nats-Rollup"
    MSG_ROLLUP_SUBJECT = "sub"

    class << self
      # digest_value returns the digest of data, as an object's: "SHA-256="
      # and the base64url of its SHA-256, like GetObjectDigestValue of nats.go.
      # @param data [String, Digest::SHA256] The data, or its SHA-256 digest.
      # @return [String]
      def digest_value(data)
        sha = data.is_a?(::Digest::SHA256) ? data.digest : ::Digest::SHA256.digest(data)
        "#{DIGEST_TYPE}#{Base64.urlsafe_encode64(sha)}"
      end

      # decode_digest returns the SHA-256 of an object's digest, like
      # DecodeObjectDigest of nats.go.
      # @param digest [String]
      # @return [String] The SHA-256, as 32 bytes.
      # @raise [InvalidDigestFormatError] When the digest has no type.
      def decode_digest(digest)
        _, value = digest.to_s.split("=", 2)
        raise InvalidDigestFormatError if value.nil?

        Base64.urlsafe_decode64(value)
      rescue ArgumentError
        raise InvalidDigestFormatError
      end
    end

    # @return [String] Name of the object store.
    attr_reader :bucket

    def initialize(opts = {})
      @bucket = opts[:name]
      @stream = opts[:stream]
      @js = opts[:js]
      @direct = opts[:direct]
    end

    # put stores an object, replacing the object of the same name, like Put
    # of nats.go.
    # @param meta [API::ObjectMeta, Hash, String] Information about the object, or its name.
    # @param data [String, IO] The data, or an IO from which to read it until its end.
    # @return [API::ObjectInfo]
    # @raise [BadObjectMetaError] When the object has no name.
    # @raise [LinkNotAllowedError] When the options have a link.
    def put(meta, data = "")
      meta = to_meta(meta)
      raise BadObjectMetaError if meta.name.nil? || meta.name.empty?

      options = meta.options ? meta.options.dup : API::ObjectMetaOptions.new
      raise LinkNotAllowedError if options.link
      options.max_chunk_size = DEFAULT_CHUNK_SIZE if options.max_chunk_size.nil? || options.max_chunk_size <= 0

      # A new nuid puts the chunks on a new subject when the name is reused,
      # so that the earlier ones can be removed once the object is replaced.
      nuid = NATS::NUID.next
      chunk_subject = chunk_subject(nuid)
      existing = begin
        get_info(meta.name, show_deleted: true)
      rescue ObjectNotFoundError
        nil
      end

      io = data.is_a?(String) ? StringIO.new(data) : data
      sha = ::Digest::SHA256.new
      size = 0
      chunks = 0
      info = nil
      begin
        while (chunk = io.read(options.max_chunk_size)) && !chunk.empty?
          @js.publish(chunk_subject, chunk)
          sha << chunk
          size += chunk.bytesize
          chunks += 1
        end

        info = API::ObjectInfo.new(
          name: meta.name, description: meta.description, headers: meta.headers,
          metadata: meta.metadata, options: options,
          bucket: @bucket, nuid: nuid, size: size, chunks: chunks,
          digest: ObjectStore.digest_value(sha)
        )
        publish_meta(info)
      rescue
        # Remove the chunks of the object that could not be stored.
        begin
          @js.purge_stream(@stream, subject: chunk_subject)
        rescue NATS::Error
          nil
        end
        raise
      end

      # Remove the chunks of the object that this one replaces.
      if existing && !existing.deleted? && existing.nuid && !existing.nuid.empty?
        @js.purge_stream(@stream, subject: chunk_subject(existing.nuid))
      end
      info
    end

    # put_string stores a String as an object, like PutString of nats.go.
    # @return [API::ObjectInfo]
    def put_string(name, data)
      put(API::ObjectMeta.new(name: name), data.to_s)
    end

    # put_file stores the contents of a file as an object, by default named
    # by the path of the file, like PutFile of nats.go.
    # @param file [String] Path of the file.
    # @param name [String] Name of the object.
    # @return [API::ObjectInfo]
    def put_file(file, name: file)
      File.open(file, "rb") do |f|
        put(API::ObjectMeta.new(name: name), f)
      end
    end

    # get reads an object, and checks its data against its digest, like Get
    # of nats.go. A link to an object reads that object.
    # @param name [String] Name of the object.
    # @param params [Hash] Options of the get.
    # @option params [IO] :io Write the data to this IO as it comes, instead
    #   of returning it.
    # @option params [Boolean] :show_deleted Read a deleted object too.
    # @return [API::ObjectResult] The info about the object, and its data
    #   unless written to an IO.
    # @raise [ObjectNotFoundError] When the object does not exist.
    # @raise [DigestMismatchError] When the data does not match the digest.
    # @raise [CantGetBucketError] When the object is a link to an object store.
    def get(name, params = {})
      info = get_info(name, show_deleted: params[:show_deleted])
      raise BadObjectMetaError if info.nuid.nil? || info.nuid.empty?

      if info.link?
        link = info.options.link
        raise CantGetBucketError if link.name.nil? || link.name.empty?

        store = (link.bucket == @bucket) ? self : @js.object_store(link.bucket)
        return store.get(link.name, io: params[:io])
      end

      io = params[:io]
      data = io ? nil : "".b
      return API::ObjectResult.new(info: info, data: data) if info.size.to_i == 0

      sha = ::Digest::SHA256.new
      each_chunk(info) do |chunk|
        sha << chunk
        io ? io.write(chunk) : data << chunk
      end
      raise DigestMismatchError unless sha.digest == ObjectStore.decode_digest(info.digest)

      API::ObjectResult.new(info: info, data: data)
    end

    # get_bytes reads the data of an object, like GetBytes of nats.go.
    # @return [String] The data, as binary.
    def get_bytes(name, params = {})
      get(name, params.except(:io)).data
    end

    # get_string reads the data of an object as UTF-8, like GetString of nats.go.
    # @return [String]
    def get_string(name, params = {})
      get_bytes(name, params).force_encoding(Encoding::UTF_8)
    end

    # get_file writes the data of an object to a file, like GetFile of nats.go.
    # The file is removed when the object cannot be read.
    # @param name [String] Name of the object.
    # @param file [String] Path of the file.
    # @return [API::ObjectInfo]
    def get_file(name, file, params = {})
      File.open(file, "wb") do |f|
        get(name, params.merge(io: f)).info
      end
    rescue
      File.delete(file) if File.exist?(file)
      raise
    end

    # get_info returns the info about an object, like GetInfo of nats.go.
    # @param name [String] Name of the object.
    # @param params [Hash] Options of the get.
    # @option params [Boolean] :show_deleted Return the info of a deleted object too.
    # @return [API::ObjectInfo]
    # @raise [ObjectNotFoundError] When the object does not exist.
    def get_info(name, params = {})
      raise NameRequiredError if name.nil? || name.empty?

      data, time = last_meta_msg(meta_subject(name))
      info = begin
        API::ObjectInfo.from_json(data)
      rescue JSON::ParserError, ArgumentError, TypeError
        raise BadObjectMetaError
      end
      raise ObjectNotFoundError if info.deleted? && !params[:show_deleted]

      info.mtime = time
      info
    end

    # update_meta changes the name, description, headers and metadata of an
    # object, but not its options, like UpdateMeta of nats.go.
    # @param name [String] Name of the object.
    # @param meta [API::ObjectMeta, Hash] The new information about the object.
    # @return [API::ObjectInfo]
    # @raise [UpdateMetaDeletedError] When the object does not exist.
    # @raise [ObjectAlreadyExistsError] When renaming to the name of another object.
    def update_meta(name, meta)
      meta = to_meta(meta)
      info = begin
        get_info(name)
      rescue ObjectNotFoundError
        raise UpdateMetaDeletedError
      end

      if name != meta.name
        existing = begin
          get_info(meta.name, show_deleted: true)
        rescue ObjectNotFoundError
          nil
        end
        raise ObjectAlreadyExistsError if existing && !existing.deleted?
      end

      info.name = meta.name
      info.description = meta.description
      info.headers = API.normalize_headers(meta.headers)
      info.metadata = meta.metadata
      publish_meta(info)

      # The meta information is now under the new name.
      @js.purge_stream(@stream, subject: meta_subject(name)) if name != meta.name
      info
    end

    # delete marks an object as deleted and removes its data, like Delete of nats.go.
    # @param name [String] Name of the object.
    # @return [Boolean]
    # @raise [ObjectNotFoundError] When the object does not exist.
    def delete(name)
      info = get_info(name, show_deleted: true)
      raise BadObjectMetaError if info.nuid.nil? || info.nuid.empty?

      info.deleted = true
      info.size = 0
      info.chunks = 0
      info.digest = nil
      publish_meta(info)

      @js.purge_stream(@stream, subject: chunk_subject(info.nuid))
      true
    end

    # add_link adds an object that links to another object, which get reads
    # in its stead, like AddLink of nats.go.
    # @param name [String] Name of the link.
    # @param obj [API::ObjectInfo] The object to link to, from get_info.
    # @return [API::ObjectInfo]
    # @raise [ObjectAlreadyExistsError] When an object, not a link, has the name.
    def add_link(name, obj)
      raise NameRequiredError if name.nil? || name.empty?
      raise ObjectRequiredError if obj.nil? || obj.name.nil? || obj.name.empty?
      raise NoLinkToDeletedError if obj.deleted?
      raise NoLinkToLinkError if obj.link?

      link_to(name, API::ObjectLink.new(bucket: obj.bucket, name: obj.name))
    end

    # add_bucket_link adds an object that links to another object store,
    # like AddBucketLink of nats.go.
    # @param name [String] Name of the link.
    # @param store [ObjectStore] The object store to link to.
    # @return [API::ObjectInfo]
    # @raise [ObjectAlreadyExistsError] When an object, not a link, has the name.
    def add_bucket_link(name, store)
      raise NameRequiredError if name.nil? || name.empty?
      raise BucketRequiredError if store.nil?
      raise BucketMalformedError unless store.is_a?(ObjectStore)

      link_to(name, API::ObjectLink.new(bucket: store.bucket))
    end

    # seal seals the object store, so that it cannot change anymore, like Seal of nats.go.
    # @return [Boolean]
    def seal
      config = @js.stream_info(@stream).config.dup
      config.sealed = true
      @js.update_stream(config)
      true
    end

    # watch is signaled with the info of the objects that change, like Watch
    # of nats.go. By default it first delivers the info of every object,
    # followed by nil.
    # @param params [Hash] Options of the watch.
    # @option params [Boolean] :include_history Deliver every earlier info of the objects too.
    # @option params [Boolean] :ignore_deletes Leave out deleted objects.
    # @option params [Boolean] :updates_only Deliver only the changes made after the
    #   watch starts, with no nil.
    # @return [ObjectWatcher]
    def watch(params = {})
      # The meta information is kept like the entries of a KeyValue bucket,
      # one per object, so a KeyValue watcher delivers it.
      kv = KeyValue.new(name: @bucket, stream: @stream, pre: "$O.#{@bucket}.M.", js: @js, direct: @direct)
      watcher = kv.watch(">", params.slice(:include_history, :updates_only, :idle_heartbeat, :inactive_threshold))
      ObjectWatcher.new(watcher, ignore_deletes: params[:ignore_deletes])
    end

    # list returns the info of the objects, like List of nats.go.
    # @param params [Hash] Options of the list.
    # @option params [Boolean] :show_deleted Include deleted objects.
    # @return [Array<API::ObjectInfo>]
    # @raise [NoObjectsFoundError] When there are no objects.
    def list(params = {})
      watcher = watch(ignore_deletes: !params[:show_deleted])
      objects = []
      begin
        watcher.each do |info|
          break if info.nil?
          objects << info
        end
      ensure
        watcher.stop
      end
      raise NoObjectsFoundError if objects.empty?

      objects
    end

    # status returns the status of the object store, like Status of nats.go.
    # @return [BucketStatus]
    def status
      BucketStatus.new(@js.stream_info(@stream), @bucket)
    end

    private

    def to_meta(meta)
      case meta
      when API::ObjectMeta then meta
      when String then API::ObjectMeta.new(name: meta)
      when Hash then API::ObjectMeta.new(meta)
      else raise BadObjectMetaError
      end
    end

    def chunk_subject(nuid)
      "$O.#{@bucket}.C.#{nuid}"
    end

    def meta_subject(name)
      "$O.#{@bucket}.M.#{Base64.urlsafe_encode64(name)}"
    end

    # publish_meta stores the meta information of an object, rolling up
    # the earlier one.
    def publish_meta(info)
      @js.publish(meta_subject(info.name), info.to_json, header: {ROLLUP => MSG_ROLLUP_SUBJECT})
      # Not when the server stored it, but close.
      info.mtime = Time.now.utc
    end

    # link_to stores a link, which can replace another link, but no object.
    def link_to(name, link)
      existing = begin
        get_info(name, show_deleted: true)
      rescue ObjectNotFoundError
        nil
      end
      raise ObjectAlreadyExistsError if existing && !existing.link?

      info = API::ObjectInfo.new(
        name: name, options: API::ObjectMetaOptions.new(link: link),
        bucket: @bucket, nuid: NATS::NUID.next, size: 0, chunks: 0
      )
      publish_meta(info)
      info
    end

    # last_meta_msg returns the data of the last message on a subject, and
    # when the server stored it.
    def last_meta_msg(subject)
      if @direct
        msg = @js.get_msg(@stream, subject: subject, direct: true)
        time = msg.headers && msg.headers[JetStream::Header::TIME_STAMP]
        [msg.data, time && Time.parse(time)]
      else
        # The message got without direct gets has its time only in the response.
        resp = @js.send(:api_request, "#{@js.prefix}.STREAM.MSG.GET.#{@stream}", {last_by_subj: subject}.to_json)
        msg = resp[:message]
        [Base64.decode64(msg[:data] || ""), Time.parse(msg[:time])]
      end
    rescue NATS::JetStream::Error::StreamNotFound
      raise BucketNotFoundError
    rescue NATS::JetStream::Error::NotFound
      raise ObjectNotFoundError
    end

    # each_chunk yields the chunks of an object, one message at a time.
    def each_chunk(info)
      subject = chunk_subject(info.nuid)
      seq = 1
      info.chunks.to_i.times do
        msg = begin
          @js.get_msg(@stream, seq: seq, subject: subject, next: true, direct: @direct)
        rescue NATS::JetStream::Error::NotFound
          # Chunks are missing: the digest does not match.
          break
        end
        yield msg.data
        seq = msg.seq.to_i + 1
      end
    end
  end

  # ObjectWatcher delivers the info of the objects of an object store that
  # change, from ObjectStore#watch.
  class ObjectWatcher
    include Enumerable

    def initialize(watcher, ignore_deletes: false)
      @watcher = watcher
      @ignore_deletes = ignore_deletes
    end

    # updates returns the info of the next object that changes, or nil
    # once the initial ones were delivered.
    # @param params [Hash]
    # @option params [Float] :timeout Seconds to wait for an update, 5 by default.
    # @raise [NATS::Timeout] When there is no update in time.
    def updates(params = {})
      loop do
        entry = @watcher.updates(params)
        return nil if entry.nil?

        info = to_info(entry)
        return info if info
      end
    end

    # Implements Enumerable: yields the info of the objects that change,
    # and nil once the initial ones were delivered.
    def each
      @watcher.each do |entry|
        if entry.nil?
          yield nil
        elsif (info = to_info(entry))
          yield info
        end
      end
    end

    def stop
      @watcher.stop
    end

    private

    # to_info returns the info in an entry, or nil when it is to be left out.
    def to_info(entry)
      info = ObjectStore::API::ObjectInfo.from_json(entry.value)
      return if @ignore_deletes && info.deleted?

      info.mtime = entry.created
      info
    rescue JSON::ParserError, ArgumentError, TypeError
      # Like nats.go, skip meta information that cannot be read.
      nil
    end
  end
end

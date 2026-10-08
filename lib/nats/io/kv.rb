# frozen_string_literal: true

# Copyright 2021-2025 The NATS Authors
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

require_relative "kv/api"
require_relative "kv/bucket_status"
require_relative "kv/errors"
require_relative "kv/manager"

module NATS
  class KeyValue
    include MonitorMixin

    KV_OP = "KV-Operation"
    KV_DEL = "DEL"
    KV_PURGE = "PURGE"
    # The operation of the entries of puts, which, unlike deletes and
    # purges, carry no KV-Operation header.
    KV_PUT = "PUT"

    # The operations of entries, like KeyValueOp of nats.go. The operation
    # of an Entry is one of these Strings, which are those of KV_PUT, KV_DEL
    # and KV_PURGE.
    module Operation
      # Like KeyValuePut of nats.go.
      PUT = KV_PUT
      # Like KeyValueDelete of nats.go.
      DELETE = KV_DEL
      # Like KeyValuePurge of nats.go.
      PURGE = KV_PURGE
    end

    # The keys pattern that watches all keys, like AllKeys of nats.go.
    ALL_KEYS = ">"
    # The most revisions of a key that a bucket keeps, like
    # KeyValueMaxHistory of nats.go.
    KEY_VALUE_MAX_HISTORY = 64

    MSG_ROLLUP_SUBJECT = "sub"
    MSG_ROLLUP_ALL = "all"
    ROLLUP = "Nats-Rollup"
    # Set by the server on the markers it leaves when a key is removed by a
    # TTL or a purge (requires nats-server v2.11.0).
    MARKER_REASON = "Nats-Marker-Reason"

    VALID_BUCKET_RE = /\A[a-zA-Z0-9_-]+\z/
    VALID_KEY_RE = /\A[-\/_=.a-zA-Z0-9]+$/

    class << self
      # validate_bucket_name raises an error unless the name is that of a
      # bucket: letters, digits, "_" and "-", like nats.go.
      # @raise [BucketRequiredError] When the name is nil or empty.
      # @raise [InvalidBucketNameError] When the name is not that of a bucket.
      def validate_bucket_name(bucket)
        raise BucketRequiredError if bucket.nil? || bucket == ""
        raise InvalidBucketNameError unless bucket.is_a?(String) && bucket.match?(VALID_BUCKET_RE)
      end

      def is_valid_key(key)
        if key.nil?
          false
        elsif key.start_with?(".") || key.end_with?(".")
          false
        elsif key !~ VALID_KEY_RE
          false
        else
          true
        end
      end

      # operation_of returns the operation of an entry from the headers of
      # its message: KV_DEL or KV_PURGE for the markers of deletes and purges,
      # including those that the server leaves when a TTL removes a key,
      # the KV-Operation header of other messages, or nil for a put, whose
      # entry has the KV_PUT operation.
      def operation_of(header)
        return if header.nil?

        op = header[KV_OP]
        return op if op

        case header[MARKER_REASON]
        when "MaxAge", "Purge" then KV_PURGE
        when "Remove" then KV_DEL
        end
      end
    end

    def initialize(opts = {})
      @name = opts[:name]
      @stream = opts[:stream]
      @pre = opts[:pre]
      # Where the writes go, which differs from where the reads go for a
      # mirror, whose writes go to its origin.
      @put_pre = opts[:put_pre] || @pre
      @js = opts[:js]
      @direct = opts[:direct]
      @validate_keys = opts[:validate_keys]
    end

    # bucket returns the name of the bucket, like Bucket of nats.go.
    # @return [String]
    def bucket
      @name
    end

    # get returns the latest value for the key, as an Entry with the
    # revision, the time it was stored (created) and the KV_PUT operation.
    # @param params [Hash] Options of the get.
    # @option params [Integer] :revision Get this revision of the key, like
    #   GetRevision of nats.go.
    # @raise [KeyNotFoundError] When the key does not exist or was deleted.
    def get(key, params = {})
      raise InvalidKeyError if @validate_keys && !KeyValue.is_valid_key(key)
      entry = nil
      begin
        entry = _get(key, params)
      rescue KeyDeletedError
        raise KeyNotFoundError
      end

      entry
    end

    def _get(key, params = {})
      msg = nil
      subject = "#{@pre}#{key}"

      msg = if params[:revision]
        @js.get_msg(@stream,
          seq: params[:revision],
          direct: @direct)
      else
        @js.get_msg(@stream,
          subject: subject,
          seq: params[:revision],
          direct: @direct)
      end

      op = KeyValue.operation_of(msg.headers)
      # Direct gets have the sequence in a header, as a String.
      entry = Entry.new(bucket: @name, key: key, value: msg.data, revision: msg.seq.to_i,
        created: msg.time, operation: op || KV_PUT)

      if subject != msg.subject
        raise KeyNotFoundError.new(
          entry: entry,
          message: "expected '#{subject}', but got '#{msg.subject}'"
        )
      end

      if (op == KV_DEL) || (op == KV_PURGE)
        raise KeyDeletedError.new(entry: entry, op: op)
      end

      entry
    rescue NATS::JetStream::Error::NotFound
      raise KeyNotFoundError
    end
    private :_get

    # put will place the new value for the key into the store
    # and return the revision number.
    def put(key, value)
      raise InvalidKeyError if @validate_keys && !KeyValue.is_valid_key(key)

      ack = @js.publish("#{@put_pre}#{key}", value)
      ack.seq
    end

    # create will add the key/value pair iff it does not exist.
    # @raise [KeyExistsError] When the key exists.
    # @param params [Hash] Options of the key.
    # @option params [Integer, Symbol] :ttl Seconds after which the server
    #   removes the key, or :never, like KeyTTL of nats.go. The bucket needs
    #   limit_marker_ttl (requires nats-server v2.11.0).
    def create(key, value, params = {})
      raise InvalidKeyError if @validate_keys && !KeyValue.is_valid_key(key)

      begin
        update_revision(key, value, 0, params[:ttl])
      rescue KeyWrongLastSequenceError => err
        # In case of attempting to recreate an already deleted key,
        # the client would get a KeyWrongLastSequenceError.  When this happens,
        # it is needed to fetch latest revision number and attempt to update.
        begin
          # NOTE: This reimplements the following behavior from Go client.
          #
          #   Since we have tombstones for DEL ops for watchers, this could be from that
          #   so we need to double check.
          #
          _get(key)
        rescue KeyDeletedError => deleted
          # The error contains the metadata to recreate the deleted key
          # using its last revision.
          return update_revision(key, value, deleted.entry.revision, params[:ttl])
        end

        # Not a deleted key, so the key exists, like ErrKeyExists of nats.go.
        raise KeyExistsError.new(err.to_s.delete_prefix("nats: "))
      end
    end

    EXPECTED_LAST_SUBJECT_SEQUENCE = "Nats-Expected-Last-Subject-Sequence"
    # The err_codes of a wrong last sequence: replicated streams report it as
    # 10164 (JSStreamWrongLastSequenceConstantErr), others as 10071.
    WRONG_LAST_SEQUENCE_ERR_CODES = [10071, 10164].freeze

    # update will update the value iff the latest revision matches.
    def update(key, value, params = {})
      raise InvalidKeyError if @validate_keys && !KeyValue.is_valid_key(key)

      last = (params[:last] ||= 0)
      update_revision(key, value, last, nil)
    end

    # update_revision publishes the value iff the latest revision of the
    # key is last, with a TTL if given.
    def update_revision(key, value, last, ttl)
      hdrs = {}
      hdrs[EXPECTED_LAST_SUBJECT_SEQUENCE] = last.to_s
      ack = nil
      begin
        ack = @js.publish("#{@put_pre}#{key}", value, header: hdrs, ttl: ttl)
      rescue NATS::JetStream::Error::APIError => err
        if WRONG_LAST_SEQUENCE_ERR_CODES.include?(err.err_code)
          raise KeyWrongLastSequenceError.new(err.description)
        else
          raise err
        end
      end

      ack.seq
    end
    private :update_revision

    # delete will place a delete marker and leave all previous revisions,
    # like Delete of nats.go.
    # @param params [Hash] Options of the delete.
    # @option params [Integer] :last Delete only if this is the latest
    #   revision of the key, like LastRevision of nats.go.
    # @return [Integer] The revision of the delete marker.
    # @raise [TTLOnDeleteNotSupportedError] When given a :ttl, which only
    #   purge takes.
    # @raise [NATS::JetStream::Error::WrongLastSequence] When :last is not
    #   the latest revision.
    def delete(key, params = {})
      raise InvalidKeyError if @validate_keys && !KeyValue.is_valid_key(key)
      raise TTLOnDeleteNotSupportedError if params[:ttl]

      hdrs = {}
      hdrs[KV_OP] = KV_DEL
      last = (params[:last] ||= 0)
      if last > 0
        hdrs[EXPECTED_LAST_SUBJECT_SEQUENCE] = last.to_s
      end
      ack = @js.publish("#{@put_pre}#{key}", header: hdrs)

      ack.seq
    end

    # purge will remove the key and all revisions, like Purge of nats.go.
    # @param params [Hash] Options of the purge.
    # @option params [Integer, Symbol] :ttl Seconds after which the server
    #   removes the purge marker, or :never, like PurgeTTL of nats.go. The
    #   bucket needs limit_marker_ttl (requires nats-server v2.11.0).
    # @option params [Integer] :last Purge only if this is the latest
    #   revision of the key, like LastRevision of nats.go, as delete does.
    # @return [NATS::JetStream::PubAck] The ack of the purge marker, whose
    #   seq is its revision.
    # @raise [NATS::JetStream::Error::WrongLastSequence] When :last is not
    #   the latest revision.
    def purge(key, params = {})
      raise InvalidKeyError if @validate_keys && !KeyValue.is_valid_key(key)

      hdrs = {}
      hdrs[KV_OP] = KV_PURGE
      hdrs[ROLLUP] = MSG_ROLLUP_SUBJECT
      last = params[:last] || 0
      hdrs[EXPECTED_LAST_SUBJECT_SEQUENCE] = last.to_s if last > 0
      @js.publish("#{@put_pre}#{key}", header: hdrs, ttl: params[:ttl])
    end

    # How old the delete and purge markers that purge_deletes removes have to
    # be by default, in seconds.
    PURGE_DELETES_MARKER_THRESHOLD = 30 * 60

    # purge_deletes removes the data of the keys that were deleted or
    # purged, like PurgeDeletes of nats.go. It also removes their markers
    # when older than :older_than, so that recent ones still reach watchers.
    # @param params [Hash] Options of the purge.
    # @option params [Numeric] :older_than Seconds after which markers are
    #   removed too, like DeleteMarkersOlderThan of nats.go: 30 minutes when
    #   nil or 0, and all markers when negative.
    # @return [nil]
    def purge_deletes(params = {})
      older_than = params[:older_than] || 0
      older_than = PURGE_DELETES_MARKER_THRESHOLD if older_than == 0
      limit = Time.now - older_than if older_than > 0

      markers = []
      w = watchall
      begin
        w.each do |entry|
          break if entry.nil?
          markers << entry if (entry.operation == KV_DEL) || (entry.operation == KV_PURGE)
        end
      ensure
        # Stop before purging, so that the purges do not reach the watcher.
        w.stop
      end

      markers.each do |entry|
        keep = 1 if limit && entry.created > limit
        @js.purge_stream(@stream, subject: "#{@pre}#{entry.key}", keep: keep)
      end
      nil
    end

    # status retrieves the status and configuration of a bucket.
    def status
      info = @js.stream_info(@stream)
      BucketStatus.new(info, @name)
    end

    # Entry is a revision of a key, like KeyValueEntry of nats.go.
    #
    # @!attribute revision
    #   The sequence of the revision in the bucket's stream.
    #   @return [Integer]
    # @!attribute delta
    #   How many revisions a watcher has yet to get after this one, nil
    #   from get.
    #   @return [Integer, nil]
    # @!attribute created
    #   When the bucket stored the revision.
    #   @return [Time]
    # @!attribute operation
    #   What made the revision: Operation::PUT ("PUT"), Operation::DELETE
    #   ("DEL") or Operation::PURGE ("PURGE").
    #   @return [String]
    Entry = Struct.new(:bucket, :key, :value, :revision, :delta, :created, :operation, keyword_init: true) do
      def initialize(opts = {})
        rem = opts.keys - members
        opts.delete_if { |k| rem.include?(k) }
        super
      end
    end

    # watch will be signaled when any key is updated.
    def watchall(params = {})
      watch(ALL_KEYS, params)
    end

    # keys returns the keys of the bucket, like Keys of nats.go, as an
    # Enumerator that goes through them once, or yields each to a block.
    # It raises NoKeysFoundError when there are none, as Keys does. The
    # watcher that it lists them with stops once they are listed, or when
    # the iteration is left early, as with break or take; list_keys gives a
    # lister that can also be stopped from elsewhere.
    # @param params [Hash, Array<String>, String] Options of the watch, or
    #   the filters of the keys to list (requires nats-server v2.10.0 for
    #   more than one), which a Hash takes as :filters.
    # @return [Enumerator<String>]
    # @raise [NoKeysFoundError] When there are no keys.
    def keys(params = {}, &block)
      params = {filters: params} unless params.is_a?(Hash)
      params = params.dup
      filters = params.delete(:filters)
      lister = filters ? list_keys_filtered(*filters, **params) : list_keys(params)

      enum = Enumerator.new do |y|
        got_keys = false
        lister.each do |key|
          got_keys = true
          y << key
        end
        raise NoKeysFoundError unless got_keys
      end
      return enum unless block

      enum.each(&block)
    end

    # list_keys returns a lister of the keys of the bucket, like ListKeys of
    # nats.go. Unlike keys, it lists no keys, rather than raising, when the
    # bucket has none.
    # @param params [Hash] Options of the watch, such as :resume_from_revision.
    # @return [KeyLister]
    def list_keys(params = {})
      params = params.merge(ignore_deletes: true, meta_only: true)
      KeyLister.new(watchall(params))
    end

    # list_keys_filtered returns a lister of the keys of the bucket that
    # match any of the filters, like ListKeysFiltered of nats.go. Without
    # filters, it lists all keys. More than one filter requires nats-server
    # v2.10.0.
    # @param filters [Array<String>] Patterns of the keys, such as "a.*".
    # @return [KeyLister]
    def list_keys_filtered(*filters, **params)
      params = params.merge(ignore_deletes: true, meta_only: true)
      KeyLister.new(watch(filters.flatten, params))
    end

    # history retrieves the entries so far for a key.
    def history(key, params = {})
      params[:include_history] = true
      w = watch(key, params)
      got_keys = false

      Enumerator.new do |y|
        w.each do |entry|
          break if entry.nil?
          got_keys = true
          y << entry
        end
        w.stop
        raise NoKeysFoundError unless got_keys
      end
    end

    STATUS_HDR = "Status"
    DESC_HDR = "Description"
    CTRL_STATUS = "100"
    LAST_CONSUMER_SEQ_HDR = "Nats-Last-Consumer"
    LAST_STREAM_SEQ_HDR = "Nats-Last-Stream"
    CONSUMER_STALLED_HDR = "Nats-Consumer-Stalled"

    # watch will be signaled when a key that matches the keys
    # pattern is updated. keys can also be an Array of patterns
    # (requires nats-server v2.10.0); an empty Array watches all keys.
    # The first update after starting the watch is nil in case
    # there are no pending updates.
    # @param params [Hash] Options of the watch.
    # @option params [Boolean] :include_history Deliver every revision of the keys, not just the latest.
    # @option params [Boolean] :ignore_deletes Leave out deletes and purges.
    # @option params [Boolean] :meta_only Deliver the entries without their values.
    # @option params [Boolean] :updates_only Deliver only the updates made after the
    #   watch starts, like UpdatesOnly of nats.go; there is then no nil update.
    # @option params [Integer] :resume_from_revision Deliver the entries from
    #   this revision on, like ResumeFromRevision of nats.go.
    def watch(keys, params = {})
      params[:meta_only] ||= false
      params[:include_history] ||= false
      params[:ignore_deletes] ||= false
      params[:idle_heartbeat] ||= 5 # seconds
      params[:inactive_threshold] ||= 5 * 60 # 5 minutes
      subject = if keys.is_a?(Array)
        keys = [ALL_KEYS] if keys.empty?
        keys.map { |key| "#{@pre}#{key}" }
      else
        "#{@pre}#{keys}"
      end
      init_setup = new_cond
      init_setup_done = false
      nc = @js.nc
      watcher = KeyWatcher.new(@js)

      # Like nats.go, a revision to resume from comes before updates_only,
      # which comes before the history.
      resume_from = params[:resume_from_revision]
      resume_from = nil unless resume_from&.positive?
      deliver_policy = if resume_from
        "by_start_sequence"
      elsif params[:updates_only]
        "new"
      elsif !params[:include_history]
        "last_per_subject"
      end
      if resume_from
        # Should the consumer have to be recreated before the first entry,
        # it resumes from the same revision.
        watcher._sseq = resume_from - 1
      elsif params[:updates_only]
        # There are no initial entries, so no nil update to mark their end.
        watcher._init_done = true
      end

      ordered = {
        # basic ordered consumer.
        flow_control: true,
        ack_policy: "none",
        max_deliver: 1,
        ack_wait: 22 * 3600,
        idle_heartbeat: params[:idle_heartbeat],
        num_replicas: 1,
        mem_storage: true,
        manual_ack: true,
        # watch related options.
        deliver_policy: deliver_policy,
        opt_start_seq: resume_from,
        headers_only: params[:meta_only],
        inactive_threshold: params[:inactive_threshold]
      }

      # watch_updates callback.
      # It takes the control messages itself, for its own heartbeat checks.
      sub = @js.subscribe(subject, stream: @stream, config: ordered, _ctrl_msgs: true) do |msg|
        synchronize do
          if !init_setup_done
            init_setup.wait(@js.opts[:timeout])
          end
        end

        # Control Message like Heartbeats and Flow Control
        status = msg.header[STATUS_HDR] unless msg.header.nil?
        if !status.nil? && status == CTRL_STATUS
          desc = msg.header[DESC_HDR]
          if desc.start_with?("Idle")
            # A watcher is active if it continues to receive Idle Heartbeat messages.
            #
            # Status: 100
            # Description: Idle Heartbeat
            # Nats-Last-Consumer: 185
            # Nats-Last-Stream: 185
            #
            watcher.synchronize { watcher._active = true }
          elsif desc.start_with?("FlowControl")
            # HMSG _INBOX.q6Y3JAFxOnNJi4QdwQnFtg 2 $JS.FC.KV_TEST.t00CunIG.GT4W 36 36
            # NATS/1.0 100 FlowControl Request
            nc.publish(msg.reply)
          end
          # Skip processing the control message
          next
        end

        # Track sequences
        meta = msg.metadata
        watcher.synchronize { watcher._active = true }
        # Track the sequences
        watcher.synchronize do
          watcher._dseq = meta.sequence.consumer + 1
          watcher._sseq = meta.sequence.stream
        end

        # Keys() handling
        op = KeyValue.operation_of(msg.header)
        if params[:ignore_deletes] && ((op == KV_PURGE) || (op == KV_DEL))
          if (meta.num_pending == 0) && !watcher._init_done
            # Push this to unblock enumerators.
            watcher._updates.push(nil)
            watcher._init_done = true
          end
          next
        end

        # Convert the msg into an Entry.
        key = msg.subject[@pre.size...msg.subject.size]
        entry = Entry.new(
          bucket: @name,
          key: key,
          value: msg.data,
          revision: meta.sequence.stream,
          delta: meta.num_pending,
          created: meta.timestamp,
          operation: op || KV_PUT
        )
        watcher._updates.push(entry)

        # When there are no more updates send an empty marker
        # to signal that it is done, this will unblock iterators.
        if (meta.num_pending == 0) && !watcher._init_done
          watcher._updates.push(nil)
          watcher._init_done = true
        end
      end # end of callback
      watcher._sub = sub

      # Snapshot the deliver subject for the consumer.
      deliver_subject = sub.subject

      # Check from consumer info what is the number of messages
      # awaiting to be consumed to send the initial signal marker.
      stream_name = nil
      begin
        cinfo = sub.consumer_info
        stream_name = cinfo.stream_name
        # Snapshot the keys filter too: subscribe set it on the consumer,
        # not on ordered, and a recreated consumer needs it.
        filter = cinfo.config.to_h.slice(:filter_subject, :filter_subjects)

        if params[:updates_only] && !resume_from
          # Should the consumer have to be recreated before the first entry,
          # it starts after the entries that were there before the watch.
          watcher.synchronize { watcher._sseq = [watcher._sseq, cinfo.delivered.stream_seq].max }
        end

        synchronize do
          init_setup_done = true
          # If no delivered and/or pending messages, then signal
          # that this is the start.
          # The consumer subscription will start receiving messages
          # so need to check those that have already made it.
          received = sub.delivered
          init_setup.signal

          # When there are no more updates send an empty marker
          # to signal that it is done, this will unblock iterators.
          if (cinfo.num_pending == 0) && (received == 0) && !watcher._init_done
            watcher._updates.push(nil)
            watcher._init_done = true
          end
        end
      rescue => err
        # cancel init
        sub.unsubscribe
        raise err
      end

      # Need to handle reconnect if missing too many heartbeats.
      hb_interval = params[:idle_heartbeat] * 2
      watcher._hb_task = Concurrent::TimerTask.new(execution_interval: hb_interval) do |task|
        task.shutdown if nc.closed?
        next unless nc.connected? && !nc.draining?

        # Wait for all idle heartbeats to be received, one of them would have
        # toggled the state of the consumer back to being active.
        active = watcher.synchronize {
          current = watcher._active
          # A heartbeat or another incoming message needs to toggle back.
          watcher._active = false
          current
        }
        if !active
          ccreq = ordered.merge(filter)
          ccreq[:deliver_policy] = "by_start_sequence"
          # Resume after the last entry. With none yet, that is the start of
          # the stream, so earlier revisions of the keys are replayed too.
          ccreq[:opt_start_seq] = watcher._sseq + 1
          ccreq[:deliver_subject] = deliver_subject
          ccreq[:idle_heartbeat] = ordered[:idle_heartbeat]
          ccreq[:inactive_threshold] = ordered[:inactive_threshold]

          should_recreate = false
          begin
            # Check if the original is still present, if it is then do not recreate.
            begin
              sub.consumer_info
            rescue ::NATS::JetStream::Error::ConsumerNotFound => e
              e.stream ||= sub.jsi.stream
              e.consumer ||= sub.jsi.consumer
              @js.nc.send(:err_cb_call, @js.nc, e, sub)
              should_recreate = true
            end
            next unless should_recreate

            # Recreate consumer that went away after a restart.
            cinfo = @js.add_consumer(stream_name, ccreq)
            sub.jsi.consumer = cinfo.name
            watcher.synchronize { watcher._dseq = 1 }
          rescue => e
            # Dispatch to the error NATS client error callback.
            @js.nc.send(:err_cb_call, @js.nc, e, sub)
          end
        end
      rescue => e
        # WRN: Unexpected error
        @js.nc.send(:err_cb_call, @js.nc, e, sub)
      end
      watcher._hb_task.execute

      watcher
    end
  end

  # KeyLister lists the keys of a bucket, like KeyLister of nats.go: each
  # yields them once, after which, or when left early, the lister stops
  # its watcher. stop stops it from anywhere, ending the listing.
  class KeyLister
    include Enumerable

    def initialize(watcher)
      @watcher = watcher
      @updates = watcher._updates
      @mon = Monitor.new
      @stopped = false
    end

    # each yields the keys, like Keys of nats.go, until they are all
    # listed or the lister is stopped.
    # @yieldparam key [String]
    def each
      return enum_for(:each) unless block_given?

      begin
        until stopped?
          entry = @updates.pop
          # The nil update marks the end of the keys.
          break if entry.nil? || stopped?
          yield entry.key
        end
      ensure
        stop
      end
      self
    end
    alias_method :keys, :each

    # stop stops the watcher of the lister, like Stop of nats.go. A listing
    # under way ends.
    def stop
      @mon.synchronize do
        return if @stopped
        @stopped = true
      end
      @watcher.stop
      # The entries that the watcher still gets go to a queue that never
      # fills, rather than block their subscription. Clearing the lister's
      # queue wakes an entry waiting for room in it, and the nil a listing
      # that waits for keys.
      @watcher._updates = Thread::Queue.new
      @updates.clear
      begin
        @updates.push(nil, true)
      rescue ThreadError
        # A full queue wakes it anyway.
      end
      nil
    end

    # Whether the lister is stopped, which it is once the keys are listed.
    def stopped?
      @mon.synchronize { @stopped }
    end
  end

  class KeyWatcher
    include MonitorMixin
    include Enumerable

    attr_accessor :received, :pending, :_sub, :_updates, :_init_done, :_watcher_cond
    attr_accessor :_sseq, :_dseq, :_active, :_hb_task

    def initialize(js)
      super() # required to initialize monitor
      @js = js
      @_sub = nil
      @_updates = SizedQueue.new(256)
      @_init_done = false
      @pending = nil
      # Ordered consumer related
      @_dseq = 1
      @_sseq = 0
      @_cmeta = nil
      @_fcr = 0
      @_fciseq = 0
      @_active = true
      @_hb_task = nil
    end

    def stop
      @_hb_task.shutdown
      @_sub.unsubscribe
    end

    def updates(params = {})
      params[:timeout] ||= 5
      result = nil
      MonotonicTime.with_nats_timeout(params[:timeout]) do
        result = @_updates.pop(timeout: params[:timeout])
      end

      result
    end

    # Implements Enumerable.
    def each
      loop do
        result = @_updates.pop
        yield result
      end
    end

    def take(n)
      super.take(n).reject { |entry| entry.nil? }
    end
  end
end

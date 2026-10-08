# frozen_string_literal: true

# Copyright 2021 The NATS Authors
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
require_relative "kv"
require_relative "object_store"
require_relative "jetstream/api"
require_relative "jetstream/batch_get"
require_relative "jetstream/batch_publisher"
require_relative "jetstream/consume"
require_relative "jetstream/consumer"
require_relative "jetstream/errors"
require_relative "jetstream/fast_publisher"
require_relative "jetstream/header"
require_relative "jetstream/js"
require_relative "jetstream/manager"
require_relative "jetstream/message_batch"
require_relative "jetstream/msg"
require_relative "jetstream/ordered_consumer"
require_relative "jetstream/pub_ack_future"
require_relative "jetstream/pull_subscription"
require_relative "jetstream/push_subscription"
require_relative "jetstream/stream"

module NATS
  # JetStream returns a context with a similar API as the NATS::Client
  # but with enhanced functions to persist and consume messages from
  # the NATS JetStream engine.
  #
  # @example
  #   nc = NATS.connect("demo.nats.io")
  #   js = nc.jetstream()
  #
  class JetStream
    # The prefix of the subjects of the JetStream API, which a context uses
    # unless given a prefix or a domain, like DefaultAPIPrefix of nats.go,
    # without its trailing dot.
    DEFAULT_API_PREFIX = "$JS.API"

    # How many times publish retries a message that no stream responded to,
    # like DefaultPubRetryAttempts of nats.go.
    DEFAULT_PUB_RETRY_ATTEMPTS = 2

    # How long, in seconds, publish waits before it retries a message that no
    # stream responded to, like DefaultPubRetryWait of nats.go.
    DEFAULT_PUB_RETRY_WAIT = 0.25

    # How many messages published with publish_async may await their acks
    # before publish_async stalls, unless given, like the default of
    # PublishAsyncMaxPending of nats.go.
    DEFAULT_PUB_ASYNC_MAX_PENDING = 4000

    # How long, in seconds, publish_async stalls before it raises
    # TooManyStalledMsgs, unless given, like the default stall wait of nats.go.
    DEFAULT_PUB_ASYNC_STALL_WAIT = 0.2

    # The options of a publish that set the id of the message and what the
    # stream has to have, as those of a batch message.
    EXPECT_OPTIONS = [:msg_id, :expected_last_seq, :expected_last_subject_seq, :expected_last_subject].freeze
    private_constant :EXPECT_OPTIONS

    attr_reader :opts, :prefix, :nc

    # Create a new JetStream context for a NATS connection.
    #
    # @param conn [NATS::Client]
    # @param params [Hash] Options to customize JetStream context.
    # @option params [String] :prefix JetStream API prefix to use for the requests.
    # @option params [String] :domain JetStream Domain to use for the requests.
    # @option params [Float] :timeout Default timeout to use for JS requests.
    # @option params [Integer] :retry_attempts Default retry_attempts of publish, 2 unless given.
    # @option params [Float] :retry_wait Default retry_wait of publish, in seconds, 0.25 unless given.
    # @option params [Integer] :publish_async_max_pending How many messages
    #   published with publish_async may await their acks before it stalls,
    #   like PublishAsyncMaxPending of nats.go: 4000 unless given.
    # @option params [Float] :publish_async_stall_wait Default stall_wait of publish_async, in seconds, 0.2 unless given.
    # @option params [Float] :publish_async_timeout Default timeout of
    #   publish_async, in seconds, like PublishAsyncTimeout of nats.go: none unless given.
    # @option params [Proc] :publish_async_err_handler Called with the
    #   message and the error of each publish_async that fails, like
    #   PublishAsyncErrHandler of nats.go.
    # @option params [Proc] :publish_async_ack_handler Called with the
    #   message and the PubAck of each publish_async that the stream acks,
    #   once its future has the ack, like WithPublishAsyncAckHandler of
    #   nats.go. It runs on the thread that takes the acks, so it should not
    #   block.
    # @option params [Hash] :client_trace Callbacks that trace the requests
    #   to the JetStream API, like WithClientTrace of nats.go:
    #   :request_sent is called with the subject and the payload of each
    #   request before it is sent, and :response_received with the subject,
    #   the payload and the header of each response, or with the subject
    #   and the payload only when it takes two arguments. Publishes, pulls
    #   and acks are not traced, as in nats.go.
    def initialize(conn, params = {})
      @nc = conn
      @prefix = if params[:prefix]
        params[:prefix]
      elsif params[:domain]
        "$JS.#{params[:domain]}.API"
      else
        DEFAULT_API_PREFIX
      end
      @opts = params
      @opts[:timeout] ||= 5 # seconds
      params[:prefix] = @prefix
      init_client_trace
      init_async_publisher

      # Include JetStream::Manager
      extend Manager
      extend KeyValue::Manager
      extend ObjectStore::Manager
    end

    # PubAck is the API response from a successfully published message.
    #
    # @!attribute [stream] stream
    #   @return [String] Name of the stream that processed the published message.
    # @!attribute [seq] seq
    #   @return [Fixnum] Sequence of the message in the stream.
    # @!attribute [duplicate] duplicate
    #   @return [Boolean] Indicates whether the published message is a duplicate.
    # @!attribute [domain] domain
    #   @return [String] JetStream Domain that processed the ack response.
    # @!attribute [val] val
    #   @return [String] Value of the counter after the increment, set when publishing to a stream with counters enabled, unless the message was a duplicate.
    # @!attribute [batch] batch
    #   @return [String] ID of the batch, set on the ack of an atomic batch commit.
    # @!attribute [count] count
    #   @return [Integer] Number of messages the batch stored, set on the ack of an atomic batch commit.
    PubAck = Struct.new(:stream, :seq, :duplicate, :domain, :val, :batch, :count,
      keyword_init: true) do
      # Fields added by newer servers are ignored, so that they cannot break publish.
      def initialize(opts = {})
        super(**opts.slice(*members))
      end
    end

    # publish produces a message for JetStream.
    #
    # @param subject [String] The subject from a stream where the message will be sent.
    # @param payload [String] The payload of the message.
    # @param params [Hash] Options to customize the publish message request.
    # @option params [Float] :timeout Time to wait for an PubAck response or an error.
    # @option params [Integer] :retry_attempts How many times to send the
    #   message again when no stream responds, as when the stream is
    #   electing a leader, like RetryAttempts of nats.go: 2 by default, and
    #   for as long as the timeout allows when negative.
    # @option params [Float] :retry_wait Seconds to wait before each retry,
    #   like RetryWait of nats.go: 0.25 by default. A retry whose wait would
    #   not end before the timeout is not made.
    # @option params [Hash] :header NATS Headers to use for the message; the
    #   options below replace those that they set.
    # @option params [String] :stream Expected Stream to which the message is being published.
    # @option params [String] :msg_id Id of the message, which the stream
    #   stores only once within its duplicate_window, like WithMsgID of nats.go.
    # @option params [Integer] :expected_last_seq Sequence that the last
    #   message of the stream has to have, like WithExpectLastSequence of nats.go.
    # @option params [Integer] :expected_last_subject_seq Sequence that the
    #   last message on the subject has to have, 0 for none, like
    #   WithExpectLastSequencePerSubject of nats.go.
    # @option params [String] :expected_last_subject Subject, which can
    #   have wildcards, whose last message expected_last_subject_seq is
    #   checked against instead of the subject of the message, like
    #   WithExpectLastSequenceForSubject of nats.go (requires nats-server
    #   v2.11.0); it needs expected_last_subject_seq.
    # @option params [String] :expected_last_msg_id Id that the last message
    #   of the stream has to have, like WithExpectLastMsgID of nats.go.
    # @option params [Integer, Symbol] :ttl Seconds after which the stream
    #   removes the message, from 1 to 2**32, or :never to keep it past the max_age of
    #   the stream. The stream needs allow_msg_ttl (requires nats-server v2.11.0).
    # @option params [Hash] :schedule Makes the message a schedule, which
    #   publishes it to the subject given as :target: once at the Time given
    #   as :at; every so many whole seconds, given as :every; or on a :cron
    #   expression with seconds, such as "0 30 * * * *", or "@hourly",
    #   "@daily", "@weekly", "@monthly" or "@yearly", in UTC or the IANA
    #   :time_zone, which only cron schedules take. :at is sent to the
    #   nanosecond. :source publishes the last message of that subject
    #   instead, :ttl gives the published messages a TTL, like the ttl
    #   option, and rollup: true rolls up the target with each. The target
    #   and source have to be subjects of the stream, which needs
    #   allow_msg_schedules, and allow_msg_ttl for :ttl. Another schedule
    #   on the subject replaces the schedule, and deleting its message stops
    #   it. Requires nats-server v2.12.0 for :at, :target and :ttl, and
    #   v2.14.0 for the others; v2.12 ignores :source and :rollup.
    # @raise [NATS::Timeout] When it takes too long to receive an ack response.
    # @raise [ArgumentError] When an option is invalid, before the message is sent.
    # @raise [NATS::JetStream::Error::APIError] When the stream refuses the
    #   message, as a stream that does not allow TTLs refuses one with a TTL.
    # @raise [NATS::JetStream::Error::NoStreamResponse] When no stream takes
    #   the subject, after the retries.
    # @return [PubAck] The pub ack response.
    def publish(subject, payload = "", **params)
      sync_publish(subject, payload, params[:header], params)
    end

    # publish_msg produces a NATS::Msg for JetStream, with its subject, data
    # and header, and waits for its ack, like PublishMsg of nats.go. The
    # message is not changed: the options add to a copy of its header, and
    # its reply is not used.
    #
    # @example
    #   msg = NATS::Msg.new(subject: "orders.new", data: "order", header: {"Kind" => "new"})
    #   ack = js.publish_msg(msg, stream: "ORDERS")
    #
    # @param msg [NATS::Msg] The message to publish to a subject of a stream.
    # @param params [Hash] The options of publish, except :header.
    # @raise [TypeError] When msg is not a NATS::Msg.
    # @raise [ArgumentError] When an option is invalid, before the message is sent.
    # @return [PubAck] The pub ack response.
    def publish_msg(msg, **params)
      check_publish_msg(msg, params)
      sync_publish(msg.subject, msg.data, msg.header, params)
    end

    # publish_async publishes a message for JetStream without waiting for
    # its ack, like PublishAsync of nats.go, and returns a future for the
    # ack. The acks come to a single subscription of the context, to a reply
    # subject with a token per message. When the server says that no stream
    # took the message, it is published again, as with publish. The futures
    # that await their acks when the connection is lost fail with
    # NATS::IO::Disconnected, like nats.go, and when it is closed with
    # NATS::IO::ConnectionClosedError.
    #
    # @example
    #   futures = 100.times.map { |i| js.publish_async("orders.new", "order #{i}") }
    #   js.publish_async_complete(timeout: 5)
    #   futures.each { |future| puts future.ack&.seq || future.err }
    #
    # @param subject [String] The subject from a stream where the message will be sent.
    # @param payload [String] The payload of the message.
    # @param params [Hash] Options to customize the publish, as those of
    #   publish: :header, :stream, :msg_id, :expected_last_seq,
    #   :expected_last_subject_seq, :expected_last_subject,
    #   :expected_last_msg_id, :ttl, :schedule, :retry_attempts and :retry_wait.
    # @option params [Float] :timeout Seconds after which the future fails
    #   with AsyncPublishTimeout unless the message was acked, like
    #   PublishAsyncTimeout of nats.go; the :publish_async_timeout of the
    #   context, or none, unless given.
    # @option params [Float] :stall_wait Seconds to wait, while as many
    #   messages await their acks as publish_async_max_pending, for one of
    #   them to be acked, like WithStallWait of nats.go; the
    #   :publish_async_stall_wait of the context, or 0.2, unless given.
    # @raise [ArgumentError] When an option is invalid, before the message is sent.
    # @raise [NATS::JetStream::Error::TooManyStalledMsgs] When too many
    #   messages still await their acks after the stall wait. The message is
    #   not published.
    # @return [PubAckFuture]
    def publish_async(subject, payload = "", **params)
      async_publish(subject, payload, params[:header], params)
    end

    # publish_msg_async publishes a NATS::Msg for JetStream, with its
    # subject, data and header, without waiting for its ack, like
    # PublishMsgAsync of nats.go, and returns a future for the ack, as
    # publish_async does. The message is not changed: the options add to a
    # copy of its header, which the future's msg has.
    #
    # @example
    #   future = js.publish_msg_async(NATS::Msg.new(subject: "orders.new", data: "order"))
    #   future.wait(5)
    #
    # @param msg [NATS::Msg] The message to publish to a subject of a stream,
    #   which cannot have a reply, as the reply subject gets the ack.
    # @param params [Hash] The options of publish_async, except :header.
    # @raise [TypeError] When msg is not a NATS::Msg.
    # @raise [NATS::JetStream::Error::AsyncPublishReplySubjectSet] When the
    #   message has a reply, like ErrAsyncPublishReplySubjectSet of nats.go.
    # @raise [ArgumentError] When an option is invalid, before the message is sent.
    # @raise [NATS::JetStream::Error::TooManyStalledMsgs] When too many
    #   messages still await their acks after the stall wait.
    # @return [PubAckFuture]
    def publish_msg_async(msg, **params)
      check_publish_msg(msg, params)
      unless msg.reply.to_s.empty?
        raise JetStream::Error::AsyncPublishReplySubjectSet.new("nats: reply subject should be empty")
      end

      async_publish(msg.subject, msg.data, msg.header, params)
    end

    # publish_async_pending is the number of messages published with
    # publish_async that await their acks, like PublishAsyncPending of nats.go.
    # @return [Integer]
    def publish_async_pending
      @async_mon.synchronize { @async_acks.size }
    end

    # publish_async_complete waits until no message published with
    # publish_async awaits its ack, like PublishAsyncComplete of nats.go.
    # @param timeout [Float, nil] Seconds to wait, or nil to wait for as long as it takes.
    # @return [true]
    # @raise [NATS::Timeout] When messages still await their acks after the timeout.
    def publish_async_complete(timeout: nil)
      @async_mon.synchronize do
        deadline = MonotonicTime.now + timeout if timeout
        until @async_acks.empty?
          remaining = deadline - MonotonicTime.now if deadline
          raise NATS::Timeout.new("nats: timeout waiting for the async publishes to complete") if remaining && remaining <= 0

          @async_done.wait(remaining)
        end
      end
      true
    end

    # cleanup_publisher cleans up the publishing side of the context, like
    # CleanupPublisher of nats.go: it unsubscribes from the replies of
    # publish_async and fails the futures that still await their acks with
    # NATS::JetStream::Error::PublisherClosed, calling the
    # publish_async_err_handler for each. The context can still be used: the
    # next publish_async subscribes to the replies again, but the acks of
    # the earlier messages are lost.
    # @return [nil]
    def cleanup_publisher
      sub, listener, futures = @async_mon.synchronize do
        taken = [@async_sub, @async_listener, @async_acks.values]
        @async_sub = nil
        @async_prefix = nil
        @async_listener = nil
        @async_acks.keys.each { |reply| remove_async_future(reply) }
        taken
      end
      @nc.send(:remove_status_listener, listener) if listener
      begin
        sub&.unsubscribe
      rescue NATS::IO::Error
        # The connection is closed, and the subscription with it.
      end
      futures.each do |future|
        resolve_async_future(future, err: JetStream::Error::PublisherClosed.new("nats: jetstream context closed"))
      end
      nil
    end

    # subscribe binds or creates a push subscription to a JetStream push consumer.
    #
    # Like js.Subscribe of nats.go, the subscription takes the control
    # messages of the consumer, which are neither passed to the block nor
    # returned by next_msg: it answers the flow control requests once the
    # messages that came before them were delivered, and, when the consumer
    # has idle heartbeats, reports a NATS::JetStream::Error::ConsumerNotActive
    # to the error callback of the connection whenever nothing came for two
    # of them.
    #
    # @param subject [String, Array] Subject(s) from which the messages will be fetched.
    # @param params [Hash] Options to customize the PushSubscription.
    # @option params [String] :stream Name of the Stream to which the consumer belongs.
    # @option params [String] :consumer Name of the Consumer to which the PushSubscription will be bound.
    # @option params [String] :name Name of the Consumer to which the PushSubscription will be bound.
    # @option params [String] :durable Consumer durable name from where the messages will be fetched.
    # @option params [String] :queue Deliver group of the consumer, to subscribe as a queue.
    # @option params [Hash] :config Configuration for the consumer.
    # @option params [Integer, Float] :idle_heartbeat Seconds between the idle heartbeats
    #   of a consumer that it creates, unless given in :config.
    # @option params [Boolean] :flow_control Whether a consumer that it creates uses
    #   flow control.
    # @option params [Boolean] :manual_ack Leave the acks of the messages passed to
    #   the block to it, like ManualAck of nats.go; otherwise each is acked once the
    #   block returns, unless the consumer does not ack.
    # @return [NATS::JetStream::PushSubscription]
    def subscribe(subject, params = {}, &cb)
      params[:consumer] ||= params[:durable]
      params[:consumer] ||= params[:name]
      multi_filter = if subject.is_a?(Array) && (subject.size == 1)
        subject = subject.first
        false
      elsif subject.is_a?(Array) && (subject.size > 1)
        true
      end

      stream = if params[:stream].nil?
        if multi_filter
          # Use the first subject to try to find the stream.
          streams = subject.map do |s|
            find_stream_name_by_subject(s)
          rescue NATS::JetStream::Error::NotFound
            raise NATS::JetStream::Error.new("nats: could not find stream matching filter subject '#{s}'")
          end

          # Ensure that the filter subjects are not ambiguous.
          streams.uniq!
          if streams.count > 1
            raise NATS::JetStream::Error.new("nats: multiple streams matched filter subjects: #{streams}")
          end

          streams.first
        else
          find_stream_name_by_subject(subject)
        end
      else
        params[:stream]
      end

      queue = params[:queue]
      durable = params[:durable]
      manual_ack = params[:manual_ack]
      idle_heartbeat = params[:idle_heartbeat]
      flow_control = params[:flow_control]
      config = params[:config]

      if queue
        if durable && (durable != queue)
          raise NATS::JetStream::Error.new("nats: cannot create queue subscription '#{queue}' to consumer '#{durable}'")
        else
          durable = queue
        end
      end

      cinfo = nil
      consumer_found = false
      should_create = false

      if !durable
        should_create = true
      else
        begin
          cinfo = consumer_info(stream, durable)
          config = cinfo.config
          consumer_found = true
          consumer = durable
        rescue NATS::JetStream::Error::NotFound
          should_create = true
          consumer_found = false
        end
      end

      if consumer_found
        if config.deliver_subject.to_s.empty?
          raise NATS::JetStream::Error::NotPushConsumer.new("nats: consumer is not a push consumer")
        elsif !config.deliver_group
          if queue
            raise NATS::JetStream::Error.new("nats: cannot create a queue subscription for a consumer without a deliver group")
          elsif cinfo.push_bound
            raise NATS::JetStream::Error.new("nats: consumer is already bound to a subscription")
          end
        elsif !queue
          raise NATS::JetStream::Error.new("nats: cannot create a subscription for a consumer with a deliver group #{config.deliver_group}")
        elsif queue != config.deliver_group
          raise NATS::JetStream::Error.new("nats: cannot create a queue subscription #{queue} for a consumer with a deliver group #{config.deliver_group}")
        end
      elsif should_create
        # Auto-create consumer if none found.
        if config.nil?
          # Defaults
          config = JetStream::API::ConsumerConfig.new({ack_policy: "explicit"})
        elsif config.is_a?(Hash)
          config = JetStream::API::ConsumerConfig.new(config)
        elsif !config.is_a?(JetStream::API::ConsumerConfig)
          raise NATS::JetStream::Error.new("nats: invalid ConsumerConfig")
        end

        config.durable_name = durable if !config.durable_name
        config.deliver_group = queue if !config.deliver_group

        # Create inbox for push consumer.
        deliver = @nc.new_inbox
        config.deliver_subject = deliver

        # Auto created consumers use the filter subject.
        if multi_filter
          config[:filter_subjects] ||= subject
        else
          config[:filter_subject] ||= subject
        end

        # Heartbeats / FlowControl
        config.flow_control = flow_control
        if idle_heartbeat || config.idle_heartbeat
          idle_heartbeat = config.idle_heartbeat if config.idle_heartbeat
          config.idle_heartbeat = idle_heartbeat
        end

        # Auto create the consumer.
        cinfo = add_consumer(stream, config)
        consumer = cinfo.name
      end

      # Enable auto acking for async callbacks unless disabled.
      # In case ack policy is none then we also do not require to ack.
      if cb && !manual_ack && (config.ack_policy != "none")
        ocb = cb
        new_cb = proc do |msg|
          ocb.call(msg)
          begin
            msg.ack
          rescue
            JetStream::Error::MsgAlreadyAckd
          end
        end
        cb = new_cb
      end
      sub = @nc.subscribe(config.deliver_subject, queue: config.deliver_group, &cb)
      sub.extend(PushSubscription)
      sub.jsi = JS::Sub.new(
        js: self,
        stream: stream,
        consumer: consumer
      )
      # The KV watcher takes the control messages itself.
      sub.send(:start_control, config.idle_heartbeat) unless params[:_ctrl_msgs]
      sub
    end

    # pull_subscribe binds or creates a subscription to a JetStream pull consumer.
    #
    # @param subject [String, Array] Subject or subjects from which the messages will be fetched.
    # @param durable [String] Consumer durable name from where the messages will be fetched.
    # @param params [Hash] Options to customize the PullSubscription.
    # @option params [String] :stream Name of the Stream to which the consumer belongs.
    # @option params [String] :consumer Name of the Consumer to which the PullSubscription will be bound.
    # @option params [String] :name Name of the Consumer to which the PullSubscription will be bound.
    # @option params [Hash] :config Configuration for the consumer.
    # @return [NATS::JetStream::PullSubscription]
    def pull_subscribe(subject, durable, params = {})
      if (!durable || durable.empty?) && !(params[:consumer] || params[:name])
        raise JetStream::Error::InvalidDurableName.new("nats: invalid durable name")
      end
      multi_filter = if subject.is_a?(Array) && (subject.size == 1)
        subject = subject.first
        false
      elsif subject.is_a?(Array) && (subject.size > 1)
        true
      end

      params[:consumer] ||= durable
      params[:consumer] ||= params[:name]
      stream = if params[:stream].nil?
        if multi_filter
          # Use the first subject to try to find the stream.
          streams = subject.map do |s|
            find_stream_name_by_subject(s)
          rescue NATS::JetStream::Error::NotFound
            raise NATS::JetStream::Error.new("nats: could not find stream matching filter subject '#{s}'")
          end

          # Ensure that the filter subjects are not ambiguous.
          streams.uniq!
          if streams.count > 1
            raise NATS::JetStream::Error.new("nats: multiple streams matched filter subjects: #{streams}")
          end

          streams.first
        else
          find_stream_name_by_subject(subject)
        end
      else
        params[:stream]
      end
      begin
        cinfo = consumer_info(stream, params[:consumer])
        unless cinfo.config.deliver_subject.to_s.empty?
          raise JetStream::Error::NotPullConsumer.new("nats: consumer is not a pull consumer")
        end
      rescue NATS::JetStream::Error::NotFound => e
        # If attempting to bind, then this is a hard error.
        raise e if params[:stream] && !multi_filter

        config = if !params[:config]
          JetStream::API::ConsumerConfig.new
        elsif params[:config].is_a?(JetStream::API::ConsumerConfig)
          params[:config]
        else
          JetStream::API::ConsumerConfig.new(params[:config])
        end
        config[:durable_name] = durable
        config[:ack_policy] ||= JS::Config::AckExplicit
        if multi_filter
          config[:filter_subjects] ||= subject
        else
          config[:filter_subject] ||= subject
        end
        add_consumer(stream, config)
      end

      bind_pull_subscription(stream, params[:consumer])
    end

    # ordered_consumer reads the messages of a stream in order, like
    # OrderedConsumer of the nats.go jetstream package: from an ephemeral
    # pull consumer that does not ack, keeps its state in memory and has a
    # single replica, which it creates again from the next stream sequence
    # it expects whenever it misses a message, or the consumer is gone. It
    # creates the first consumer at once.
    #
    # @example Read the messages of a stream in order.
    #
    #   oc = js.ordered_consumer("ORDERS")
    #   msgs = oc.messages
    #   msg = msgs.next(timeout: 5)
    #
    # @param stream [String] Name of the stream.
    # @param params [Hash] Options to customize the ordered consumer.
    # @option params [Array<String>] :filter_subjects Subjects to read, all by default.
    # @option params [String] :deliver_policy Where to start: "all" (the default),
    #   "last", "new", "by_start_sequence", "by_start_time" or "last_per_subject".
    # @option params [Integer] :opt_start_seq Stream sequence to start at, with "by_start_sequence".
    # @option params [Time, String] :opt_start_time Time to start at, with "by_start_time".
    # @option params [String] :replay_policy "instant" (the default) or "original".
    # @option params [Integer, Float] :inactive_threshold Seconds after which the server
    #   deletes the consumer when unused, 300 by default.
    # @option params [Boolean] :headers_only Deliver the headers of the messages only,
    #   with their size in a Nats-Msg-Size header.
    # @option params [Hash] :metadata Metadata of the consumer.
    # @option params [Integer] :max_reset_attempts How many times to try creating the
    #   consumer again, for good by default; a fetch tries once.
    # @option params [String] :name_prefix Prefix of the names of the consumers, which
    #   end with a serial number; unique by default.
    # @return [NATS::JetStream::OrderedConsumer]
    # @raise [ArgumentError] When an option is invalid.
    # @raise [NATS::JetStream::Error] When the consumer cannot be created, as when the
    #   stream does not exist.
    def ordered_consumer(stream, params = {})
      OrderedConsumer.new(self, stream, params)
    end

    # stream returns a handle to a stream, with its current info, like
    # Stream of the nats.go jetstream package.
    #
    # @example Purge a stream and read the last message on a subject.
    #
    #   stream = js.stream("ORDERS")
    #   stream.purge(subject: "orders.eu")
    #   msg = stream.get_last_msg_for_subject("orders.us")
    #
    # @param name [String] Name of the stream.
    # @param params [Hash] Options of {Manager#stream_info}.
    # @return [NATS::JetStream::Stream]
    # @raise [NATS::JetStream::Error::StreamNotFound] When the stream does not exist.
    def stream(name, params = {})
      Stream.new(self, name, stream_info(name, params))
    end

    # consumer returns a handle to a pull consumer, with its current info,
    # like Consumer of the nats.go jetstream package.
    #
    # @param stream [String] Name of the stream.
    # @param name [String] Name of the consumer.
    # @param params [Hash] Options to customize API request.
    # @return [NATS::JetStream::Consumer]
    # @raise [NATS::JetStream::Error::ConsumerNotFound] When the consumer does not exist.
    # @raise [NATS::JetStream::Error::NotPullConsumer] When it is a push consumer.
    def consumer(stream, name, params = {})
      Stream.new(self, stream, nil).consumer(name, params)
    end

    # push_consumer returns a handle to a push consumer, with its current
    # info, like PushConsumer of the nats.go jetstream package.
    #
    # @param stream [String] Name of the stream.
    # @param name [String] Name of the consumer.
    # @param params [Hash] Options to customize API request.
    # @return [NATS::JetStream::PushConsumer]
    # @raise [NATS::JetStream::Error::ConsumerNotFound] When the consumer does not exist.
    # @raise [NATS::JetStream::Error::NotPushConsumer] When it is a pull consumer.
    def push_consumer(stream, name, params = {})
      Stream.new(self, stream, nil).push_consumer(name, params)
    end

    # create_or_update_consumer creates a pull consumer of a stream, or
    # updates it, and returns a handle to it, like CreateOrUpdateConsumer of
    # the nats.go jetstream package. To get the ConsumerInfo instead, as
    # create_consumer and update_consumer of the context return, use
    # {Manager#add_consumer}; {Stream#create_consumer} and
    # {Stream#update_consumer} return handles.
    #
    # @example Create a consumer and fetch its messages.
    #
    #   consumer = js.create_or_update_consumer("ORDERS", durable_name: "processor")
    #   consumer.fetch(10).each(&:ack)
    #
    # @param stream [String] Name of the stream.
    # @param config [JetStream::API::ConsumerConfig, Hash] Configuration of the consumer.
    # @param params [Hash] Options to customize API request.
    # @return [NATS::JetStream::Consumer]
    def create_or_update_consumer(stream, config, params = {})
      Stream.new(self, stream, nil).create_or_update_consumer(config, params)
    end

    # create_push_consumer creates a push consumer of a stream, which needs
    # a deliver_subject, and returns a handle to it, like CreatePushConsumer
    # of the nats.go jetstream package. Creating one that exists with the
    # same config succeeds; one with another config raises
    # ConsumerAlreadyExists.
    #
    # @example Create a push consumer and consume its messages.
    #
    #   consumer = js.create_push_consumer("ORDERS", durable_name: "dispatcher",
    #     deliver_subject: "deliver.orders")
    #   cc = consumer.consume { |msg| msg.ack }
    #
    # @param stream [String] Name of the stream.
    # @param config [JetStream::API::ConsumerConfig, Hash] Configuration of the consumer.
    # @param params [Hash] Options to customize API request.
    # @return [NATS::JetStream::PushConsumer]
    # @raise [NATS::JetStream::Error::NotPushConsumer] When the config has no deliver_subject.
    def create_push_consumer(stream, config, params = {})
      Stream.new(self, stream, nil).create_push_consumer(config, params)
    end

    # update_push_consumer updates a push consumer of a stream, and returns
    # a handle to it, like UpdatePushConsumer of the nats.go jetstream
    # package. A consumer that does not exist raises ConsumerDoesNotExist.
    # @param stream [String] Name of the stream.
    # @param config [JetStream::API::ConsumerConfig, Hash] Configuration of the consumer.
    # @param params [Hash] Options to customize API request.
    # @return [NATS::JetStream::PushConsumer]
    # @raise [NATS::JetStream::Error::NotPushConsumer] When the config has no deliver_subject.
    def update_push_consumer(stream, config, params = {})
      Stream.new(self, stream, nil).update_push_consumer(config, params)
    end

    # create_or_update_push_consumer creates a push consumer of a stream,
    # or updates it, and returns a handle to it, like
    # CreateOrUpdatePushConsumer of the nats.go jetstream package.
    # @param stream [String] Name of the stream.
    # @param config [JetStream::API::ConsumerConfig, Hash] Configuration of the consumer.
    # @param params [Hash] Options to customize API request.
    # @return [NATS::JetStream::PushConsumer]
    # @raise [NATS::JetStream::Error::NotPushConsumer] When the config has no deliver_subject.
    def create_or_update_push_consumer(stream, config, params = {})
      Stream.new(self, stream, nil).create_or_update_push_consumer(config, params)
    end

    private

    # sync_publish publishes a message and waits for its ack.
    def sync_publish(subject, payload, header, params)
      params[:timeout] ||= @opts[:timeout]
      retry_attempts, retry_wait = pub_retry(params)
      # Send message with headers.
      msg = NATS::Msg.new(subject: subject,
        data: payload || "",
        header: publish_header(params, header))

      pub_ack(request_with_retry(msg, params[:timeout], retry_attempts, retry_wait))
    end

    # async_publish publishes a message with a reply of its own and returns
    # the future for its ack.
    def async_publish(subject, payload, header, params)
      retry_attempts, retry_wait = pub_retry(params)
      timeout = params.fetch(:timeout) { @opts[:publish_async_timeout] }
      stall_wait = params.fetch(:stall_wait) { @opts.fetch(:publish_async_stall_wait, DEFAULT_PUB_ASYNC_STALL_WAIT) }
      positive_seconds!(:timeout, timeout) unless timeout.nil?
      positive_seconds!(:stall_wait, stall_wait)
      header = publish_header(params, header)

      @async_mon.synchronize do
        start_async_reply_sub unless @async_sub
        @async_tokens += 1
        msg = NATS::Msg.new(subject: subject, reply: "#{@async_prefix}#{@async_tokens.to_s(36)}",
          data: payload || "", header: header)
        future = PubAckFuture.new(msg, retry_attempts: retry_attempts, retry_wait: retry_wait, timeout: timeout)
        @async_acks[msg.reply] = future
        stall_async_publish(msg.reply, stall_wait)
        publish_async_msg(future)
      end
    end

    # check_publish_msg checks the message and the options of publish_msg
    # and publish_msg_async, which take the header of the message.
    def check_publish_msg(msg, params)
      raise TypeError, "nats: expected NATS::Msg, got #{msg.class.name}" unless msg.is_a?(NATS::Msg)
      raise ArgumentError.new("nats: the header of a NATS::Msg is published, not a header option") if params.key?(:header)
    end

    # publish_header makes the header of a publish from its options.
    def publish_header(params, header = params[:header])
      # The options add to a copy of the header, which the caller may reuse.
      options = {
        Header::EXPECTED_STREAM => (params[:stream] if params[:stream]),
        Header::MSG_TTL => (msg_ttl(params[:ttl]) if params[:ttl])
      }.compact
      options.merge!(BatchPublisher.msg_header(self, **params.slice(*EXPECT_OPTIONS)))
      unless params[:expected_last_msg_id].nil?
        options[Header::EXPECTED_LAST_MSG_ID] = BatchPublisher.option_string(:expected_last_msg_id, params[:expected_last_msg_id])
      end
      if (schedule = params[:schedule])
        raise ArgumentError.new("nats: invalid schedule #{schedule.inspect}, expected a Hash") unless schedule.is_a?(Hash)

        options.merge!(schedule_header(**schedule))
      end
      options.empty? ? header : header.to_h.merge(options)
    end

    # init_client_trace checks the callbacks of the client_trace option.
    def init_client_trace
      trace = @opts[:client_trace]
      return if trace.nil?
      raise ArgumentError.new("nats: invalid client_trace #{trace.inspect}, expected a Hash") unless trace.is_a?(Hash)

      trace.each do |name, cb|
        unless [:request_sent, :response_received].include?(name)
          raise ArgumentError.new("nats: invalid client_trace callback #{name.inspect}, expected :request_sent or :response_received")
        end
        raise ArgumentError.new("nats: invalid client_trace #{name} #{cb.inspect}, expected a callable") unless cb.nil? || cb.respond_to?(:call)
      end
    end

    # init_async_publisher sets up the state of publish_async: the futures
    # of the messages that await acks by reply subject, and the conditions
    # that stalled publishes, publish_async_complete and the timer wait on.
    def init_async_publisher
      max_pending = @opts.fetch(:publish_async_max_pending, DEFAULT_PUB_ASYNC_MAX_PENDING)
      unless max_pending.is_a?(Integer) && max_pending >= 1
        raise ArgumentError.new("nats: invalid publish_async_max_pending #{max_pending.inspect}, expected an Integer of at least 1")
      end
      err_handler = @opts[:publish_async_err_handler]
      unless err_handler.nil? || err_handler.respond_to?(:call)
        raise ArgumentError.new("nats: invalid publish_async_err_handler #{err_handler.inspect}, expected a callable")
      end
      ack_handler = @opts[:publish_async_ack_handler]
      unless ack_handler.nil? || ack_handler.respond_to?(:call)
        raise ArgumentError.new("nats: invalid publish_async_ack_handler #{ack_handler.inspect}, expected a callable")
      end

      @async_max_pending = max_pending
      @async_err_handler = err_handler
      @async_ack_handler = ack_handler
      @async_mon = Monitor.new
      @async_stall = @async_mon.new_cond
      @async_done = @async_mon.new_cond
      @async_timer_cond = @async_mon.new_cond
      @async_timer = nil
      @async_acks = {}
      @async_tokens = 0
      @async_sub = nil
      @async_prefix = nil
      @async_listener = nil
    end

    # start_async_reply_sub subscribes to the replies of all the messages
    # that publish_async publishes, as nats.go does.
    def start_async_reply_sub
      @async_prefix = "#{@nc.new_inbox}."
      @async_sub = @nc.subscribe("#{@async_prefix}*") { |msg| handle_async_reply(msg) }
      @async_listener ||= @nc.send(:add_status_listener) { |event| fail_async_futures(event) }
    end

    # fail_async_futures ends the futures that await acks when the
    # connection is lost or closed, as their acks may never come: with
    # NATS::IO::Disconnected when it reconnects, like nats.go, and with
    # NATS::IO::ConnectionClosedError once it is closed, when the replies
    # are subscribed to again by the next publish_async.
    def fail_async_futures(event)
      futures = @async_mon.synchronize do
        if event == :close
          @async_sub = nil
          @async_prefix = nil
        end
        @async_acks.values.tap { @async_acks.keys.each { |reply| remove_async_future(reply) } }
      end
      futures.each do |future|
        err = if event == :close
          NATS::IO::ConnectionClosedError.new("nats: connection closed")
        else
          NATS::IO::Disconnected.new("nats: server is disconnected")
        end
        resolve_async_future(future, err: err)
      end
    end

    # stall_async_publish waits, while more messages await their acks than
    # may, for the stall wait, and drops the message when it is up.
    def stall_async_publish(reply, stall_wait)
      deadline = MonotonicTime.now + stall_wait
      while @async_acks.size > @async_max_pending
        remaining = deadline - MonotonicTime.now
        if remaining <= 0
          @async_acks.delete(reply)
          raise JetStream::Error::TooManyStalledMsgs.new("nats: stalled with too many outstanding async published messages")
        end
        @async_stall.wait(remaining)
      end
    end

    # publish_async_msg publishes the message of a future, starting its
    # timeout over, as nats.go does. A message that cannot be published
    # ends its future with the error. The lock is held.
    def publish_async_msg(future)
      if future.timeout
        future.deadline = MonotonicTime.now + future.timeout
        wake_async_timer
      end
      begin
        @nc.publish_msg(future.msg)
      rescue
        remove_async_future(future.msg.reply)
        raise
      end
      future
    end

    # handle_async_reply resolves the future of a reply, or publishes its
    # message again when no stream responded and it has retries left.
    def handle_async_reply(msg)
      err = nil
      ack = nil
      future = nil
      @async_mon.synchronize do
        future = @async_acks[msg.subject]
        return unless future

        if msg.header && msg.header[JS::Header::Status] == JS::Status::ServiceUnavailable && msg.data.to_s.empty?
          if future.retry_attempts < 0 || future.retries < future.retry_attempts
            future.retries += 1
            future.retry_at = MonotonicTime.now + future.retry_wait
            wake_async_timer
            return
          end
          err = JetStream::Error::NoStreamResponse.new("nats: no response from stream")
        else
          begin
            ack = pub_ack(msg)
          rescue JetStream::Error => e
            err = e
          end
        end
        remove_async_future(msg.subject)
      end
      resolve_async_future(future, ack: ack, err: err)
    end

    # resolve_async_future ends the publish of a future, calling the error
    # handler when it failed, and the ack handler when it was acked. It is
    # called without holding the lock.
    def resolve_async_future(future, ack: nil, err: nil)
      return unless future.resolve(ack: ack, err: err)

      if err
        @async_err_handler&.call(future.msg, err)
      elsif ack
        @async_ack_handler&.call(future.msg, ack)
      end
    rescue => e
      # An error of the handler goes to the error callback of the connection.
      @nc.send(:err_cb_call, @nc, e, nil)
    end

    # remove_async_future forgets the future of a reply, waking stalled
    # publishes and publish_async_complete. The lock is held.
    def remove_async_future(reply)
      @async_acks.delete(reply)
      @async_stall.broadcast
      @async_done.broadcast if @async_acks.empty?
    end

    # wake_async_timer makes the timer, which retries messages and fails
    # futures past their timeout, look at the futures again, starting it
    # unless it runs. The lock is held.
    def wake_async_timer
      if @async_timer
        @async_timer_cond.signal
      else
        @async_timer = Thread.new { run_async_timer }
      end
    end

    # run_async_timer retries the messages whose retry is due and fails the
    # futures past their timeout, until no future has a retry or timeout.
    def run_async_timer
      loop do
        retries = []
        expired = []
        @async_mon.synchronize do
          now = MonotonicTime.now
          next_at = nil
          @async_acks.each do |reply, future|
            if future.deadline && future.deadline <= now
              expired << reply
            elsif future.retry_at && future.retry_at <= now
              future.retry_at = nil
              retries << future
            end
            [future.deadline, future.retry_at].compact.each { |at| next_at = at if next_at.nil? || at < next_at }
          end
          expired.map! do |reply|
            future = @async_acks[reply]
            remove_async_future(reply)
            future
          end
          if retries.empty? && expired.empty?
            if next_at.nil?
              @async_timer = nil
              return
            end
            @async_timer_cond.wait(next_at - now)
          end
        end
        retries.each do |future|
          @async_mon.synchronize { publish_async_msg(future) if @async_acks.key?(future.msg.reply) }
        rescue => e
          resolve_async_future(future, err: e)
        end
        expired.each do |future|
          resolve_async_future(future, err: JetStream::Error::AsyncPublishTimeout.new("nats: timeout waiting for ack"))
        end
      end
    end

    # positive_seconds! checks that an option is a positive number of seconds.
    def positive_seconds!(name, value)
      return if value.is_a?(Numeric) && value.positive? && value.finite?

      raise ArgumentError.new("nats: invalid #{name} #{value.inspect}, expected seconds of more than 0")
    end

    # pub_retry takes the retry options of a publish, which default to those
    # of the context.
    def pub_retry(params)
      attempts = params.fetch(:retry_attempts) { @opts.fetch(:retry_attempts, DEFAULT_PUB_RETRY_ATTEMPTS) }
      wait = params.fetch(:retry_wait) { @opts.fetch(:retry_wait, DEFAULT_PUB_RETRY_WAIT) }
      raise ArgumentError.new("nats: invalid retry_attempts #{attempts.inspect}, expected an Integer") unless attempts.is_a?(Integer)
      unless wait.is_a?(Numeric) && wait >= 0 && wait.finite?
        raise ArgumentError.new("nats: invalid retry_wait #{wait.inspect}, expected seconds of 0 or more")
      end

      [attempts, wait]
    end

    # request_with_retry sends the message of a publish, and sends it again
    # when no stream responds, as nats.go does, as long as the retry would
    # start before the timeout is up, which all of the attempts share.
    def request_with_retry(msg, timeout, attempts, wait)
      deadline = MonotonicTime.now + timeout
      retries = 0
      begin
        @nc.request_msg(msg, timeout: deadline - MonotonicTime.now)
      rescue ::NATS::IO::NoRespondersError
        if (attempts < 0 || retries < attempts) && MonotonicTime.now + wait < deadline
          retries += 1
          sleep(wait)
          retry
        end
        raise JetStream::Error::NoStreamResponse.new("nats: no response from stream")
      end
    end

    # pub_ack takes the PubAck from the response to a publish, raising the
    # error that the stream responded with instead.
    def pub_ack(resp)
      result = begin
        JSON.parse(resp.data, symbolize_names: true)
      rescue JSON::ParserError
        nil
      end
      raise JetStream::Error::InvalidJSAck.new("nats: invalid jetstream publish response") unless result.is_a?(Hash)
      raise JS.from_error(result[:error]) if result[:error]
      raise JetStream::Error::InvalidJSAck.new("nats: invalid jetstream publish response") if result[:stream].to_s.empty?

      PubAck.new(result)
    end

    # bind_pull_subscription makes a pull subscription to an existing
    # consumer. Each pull gets a reply of its own under the subscription.
    def bind_pull_subscription(stream, consumer)
      sub = @nc.subscribe("#{@nc.new_inbox}.*")
      sub.extend(PullSubscription)
      sub.jsi = JS::Sub.new(
        js: self,
        stream: stream,
        consumer: consumer,
        nms: "#{@prefix}.CONSUMER.MSG.NEXT.#{stream}.#{consumer}"
      )
      sub
    end

    # msg_ttl formats a message TTL as the server takes it. Longer TTLs than
    # 2**32 seconds, some 136 years, overflow in the server, which then
    # removes the message at once.
    def msg_ttl(ttl)
      return "never" if ttl == :never
      unless ttl.is_a?(Integer) && ttl.between?(1, 2**32)
        raise ArgumentError.new("nats: invalid ttl #{ttl.inspect}, expected whole seconds from 1 to 2**32, or :never")
      end

      ttl.to_s
    end

    # schedule_header makes the headers of a message schedule.
    def schedule_header(target:, at: nil, every: nil, cron: nil, source: nil, ttl: nil, time_zone: nil, rollup: nil)
      pattern = if at.is_a?(Time)
        "@at #{at.getutc.iso8601(9)}"
      elsif every.is_a?(Integer) && every >= 1
        "@every #{every}s"
      elsif nonempty_string?(cron)
        cron
      end
      unless pattern && [at, every, cron].compact.size == 1
        raise ArgumentError.new("nats: a schedule needs one of at: a Time, every: whole seconds from 1, or cron: an expression")
      end
      raise ArgumentError.new("nats: a schedule needs a target subject") unless nonempty_string?(target)
      raise ArgumentError.new("nats: invalid schedule source #{source.inspect}") unless source.nil? || nonempty_string?(source)
      raise ArgumentError.new("nats: invalid schedule time zone #{time_zone.inspect}") unless time_zone.nil? || nonempty_string?(time_zone)
      raise ArgumentError.new("nats: only cron: schedules take a time zone") if time_zone && !cron
      raise ArgumentError.new("nats: invalid schedule rollup #{rollup.inspect}") unless [nil, true, false].include?(rollup)

      {
        Header::SCHEDULE => pattern,
        Header::SCHEDULE_TARGET => target,
        Header::SCHEDULE_SOURCE => source,
        Header::SCHEDULE_TTL => (msg_ttl(ttl) if ttl),
        Header::SCHEDULE_TIME_ZONE => time_zone,
        Header::SCHEDULE_ROLLUP => ("sub" if rollup)
      }.compact
    end

    def nonempty_string?(value)
      value.is_a?(String) && !value.empty?
    end
  end
end

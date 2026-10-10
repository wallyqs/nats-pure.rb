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

require_relative "consumer"
require_relative "errors"

module NATS
  class JetStream
    # Stream is a handle to a JetStream stream, like the Stream of the
    # nats.go jetstream package, which js.stream returns. It operates on
    # the stream, and on its messages and consumers, without naming the
    # stream each time, and keeps the info of the stream from when it was
    # got, or last refreshed with info, as cached_info.
    #
    # @example Read the messages of a consumer of a stream.
    #
    #   stream = js.stream("ORDERS")
    #   consumer = stream.create_consumer(durable_name: "processor")
    #   consumer.fetch(10).each(&:ack)
    #
    # @!visibility public
    class Stream
      # @return [String] Name of the stream.
      attr_reader :name

      # @!visibility private
      def initialize(js, name, info)
        @js = js
        @name = name
        @info = info
      end

      # info gets the current info of the stream, and caches it. It takes
      # the options of {Manager#stream_info}, such as :subjects_filter and
      # :deleted_details. As in nats.go, the cached info is kept without the
      # subjects of :subjects_filter.
      # @param params [Hash] Options to customize API request.
      # @return [JetStream::API::StreamInfo]
      def info(params = {})
        info = @js.stream_info(@name, params)
        @info = if info.state.subjects
          cached = info.dup
          cached.state = info.state.dup.tap { |state| state.subjects = nil }
          cached.freeze
        else
          info
        end
        info
      end

      # cached_info is the info of the stream from when the handle was made,
      # or info was last called, without asking the server.
      # @return [JetStream::API::StreamInfo]
      def cached_info
        @info
      end

      # purge removes messages from the stream, like {Manager#purge_stream},
      # with the same options.
      # @param params [Hash] Options of {Manager#purge_stream}.
      # @return [JetStream::API::StreamPurgeResponse]
      def purge(params = {})
        @js.purge_stream(@name, params)
      end

      # delete_msg deletes a message of the stream, like {Manager#delete_msg}.
      # @param seq [Integer] Sequence of the message.
      # @param params [Hash] Options to customize API request.
      # @return [Boolean]
      def delete_msg(seq, params = {})
        @js.delete_msg(@name, seq, params)
      end

      # secure_delete_msg deletes a message of the stream, overwriting its
      # data, like {Manager#secure_delete_msg}.
      # @param seq [Integer] Sequence of the message.
      # @param params [Hash] Options to customize API request.
      # @return [Boolean]
      def secure_delete_msg(seq, params = {})
        @js.secure_delete_msg(@name, seq, params)
      end

      # get_msg gets a message of the stream by its sequence, like GetMsg of
      # nats.go: with :subject, the first message on that subject from the
      # sequence on, like WithGetMsgSubject. As in nats.go, it gets it
      # directly from a replica when the cached info allows direct gets.
      # @param seq [Integer] Sequence of the message.
      # @param params [Hash] Options to customize API request.
      # @option params [String] :subject Get the next message on this subject.
      # @option params [Boolean] :direct Whether to get the message directly,
      #   as the cached info allows by default.
      # @return [JetStream::API::RawStreamMsg]
      # @raise [JetStream::Error::MsgNotFound] When there is no such message.
      def get_msg(seq, params = {})
        req = {seq: seq, direct: params.fetch(:direct) { direct_get? }}
        req.merge!(subject: params[:subject], next: true) if params[:subject]
        @js.get_msg(@name, req)
      end

      # get_last_msg_for_subject gets the last message of the stream on a
      # subject, like GetLastMsgForSubject of nats.go.
      # @param subject [String] Subject of the message.
      # @param params [Hash] Options to customize API request.
      # @option params [Boolean] :direct Whether to get the message directly,
      #   as the cached info allows by default.
      # @return [JetStream::API::RawStreamMsg]
      # @raise [JetStream::Error::MsgNotFound] When there is no such message.
      def get_last_msg_for_subject(subject, params = {})
        @js.get_msg(@name, subject: subject, direct: params.fetch(:direct) { direct_get? })
      end

      # create_consumer creates a pull consumer of the stream, like
      # {Manager#create_consumer}, and returns a handle to it.
      # @param config [JetStream::API::ConsumerConfig, Hash] Configuration of the consumer.
      # @param params [Hash] Options to customize API request.
      # @return [JetStream::Consumer]
      def create_consumer(config, params = {})
        Consumer.new(@js, @name, @js.create_consumer(@name, config, params))
      end

      # update_consumer updates a pull consumer of the stream, like
      # {Manager#update_consumer}, and returns a handle to it.
      # @param config [JetStream::API::ConsumerConfig, Hash] Configuration of the consumer.
      # @param params [Hash] Options to customize API request.
      # @return [JetStream::Consumer]
      def update_consumer(config, params = {})
        Consumer.new(@js, @name, @js.update_consumer(@name, config, params))
      end

      # create_or_update_consumer creates a pull consumer of the stream, or
      # updates it, like {Manager#add_consumer}, and returns a handle to it.
      # @param config [JetStream::API::ConsumerConfig, Hash] Configuration of the consumer.
      # @param params [Hash] Options to customize API request.
      # @return [JetStream::Consumer]
      def create_or_update_consumer(config, params = {})
        Consumer.new(@js, @name, @js.add_consumer(@name, config, params))
      end

      # consumer returns a handle to a pull consumer of the stream, with its
      # current info.
      # @param name [String] Name of the consumer.
      # @param params [Hash] Options to customize API request.
      # @return [JetStream::Consumer]
      # @raise [JetStream::Error::ConsumerNotFound] When the consumer does not exist.
      # @raise [JetStream::Error::NotPullConsumer] When it is a push consumer.
      def consumer(name, params = {})
        info = @js.consumer_info(@name, name, params)
        raise Error::NotPullConsumer.new("nats: consumer is not a pull consumer") unless info.config.deliver_subject.to_s.empty?

        Consumer.new(@js, @name, info)
      end

      # create_push_consumer creates a push consumer of the stream, which
      # needs a deliver_subject, like {Manager#create_consumer}, and returns
      # a handle to it.
      # @param config [JetStream::API::ConsumerConfig, Hash] Configuration of the consumer.
      # @param params [Hash] Options to customize API request.
      # @return [JetStream::PushConsumer]
      # @raise [JetStream::Error::NotPushConsumer] When the config has no deliver_subject.
      def create_push_consumer(config, params = {})
        PushConsumer.new(@js, @name, @js.create_consumer(@name, push_config(config), params))
      end

      # update_push_consumer updates a push consumer of the stream, like
      # {Manager#update_consumer}, and returns a handle to it.
      # @param config [JetStream::API::ConsumerConfig, Hash] Configuration of the consumer.
      # @param params [Hash] Options to customize API request.
      # @return [JetStream::PushConsumer]
      # @raise [JetStream::Error::NotPushConsumer] When the config has no deliver_subject.
      def update_push_consumer(config, params = {})
        PushConsumer.new(@js, @name, @js.update_consumer(@name, push_config(config), params))
      end

      # create_or_update_push_consumer creates a push consumer of the
      # stream, or updates it, like {Manager#add_consumer}, and returns a
      # handle to it.
      # @param config [JetStream::API::ConsumerConfig, Hash] Configuration of the consumer.
      # @param params [Hash] Options to customize API request.
      # @return [JetStream::PushConsumer]
      # @raise [JetStream::Error::NotPushConsumer] When the config has no deliver_subject.
      def create_or_update_push_consumer(config, params = {})
        PushConsumer.new(@js, @name, @js.add_consumer(@name, push_config(config), params))
      end

      # push_consumer returns a handle to a push consumer of the stream,
      # with its current info.
      # @param name [String] Name of the consumer.
      # @param params [Hash] Options to customize API request.
      # @return [JetStream::PushConsumer]
      # @raise [JetStream::Error::ConsumerNotFound] When the consumer does not exist.
      # @raise [JetStream::Error::NotPushConsumer] When it is a pull consumer.
      def push_consumer(name, params = {})
        info = @js.consumer_info(@name, name, params)
        raise Error::NotPushConsumer.new("nats: consumer is not a push consumer") if info.config.deliver_subject.to_s.empty?

        PushConsumer.new(@js, @name, info)
      end

      # ordered_consumer reads the stream in order, like
      # {JetStream#ordered_consumer}, with the same options.
      # @param params [Hash] Options of {JetStream#ordered_consumer}.
      # @return [JetStream::OrderedConsumer]
      def ordered_consumer(params = {})
        @js.ordered_consumer(@name, params)
      end

      # delete_consumer deletes a consumer of the stream.
      # @param name [String] Name of the consumer.
      # @param params [Hash] Options to customize API request.
      # @return [Boolean]
      def delete_consumer(name, params = {})
        @js.delete_consumer(@name, name, params)
      end

      # pause_consumer pauses a consumer of the stream, like {Manager#pause_consumer}.
      # @param name [String] Name of the consumer.
      # @param pause_until [Time, String] When to resume.
      # @param params [Hash] Options to customize API request.
      # @return [JetStream::API::ConsumerPauseResponse]
      def pause_consumer(name, pause_until, params = {})
        @js.pause_consumer(@name, name, pause_until, params)
      end

      # resume_consumer resumes a consumer of the stream, like {Manager#resume_consumer}.
      # @param name [String] Name of the consumer.
      # @param params [Hash] Options to customize API request.
      # @return [JetStream::API::ConsumerPauseResponse]
      def resume_consumer(name, params = {})
        @js.resume_consumer(@name, name, params)
      end

      # unpin_consumer unpins a priority group of a consumer of the stream,
      # like {Manager#unpin_consumer}.
      # @param name [String] Name of the consumer.
      # @param group [String] Name of the priority group.
      # @param params [Hash] Options to customize API request.
      # @return [Boolean]
      def unpin_consumer(name, group, params = {})
        @js.unpin_consumer(@name, name, group, params)
      end

      # reset_consumer resets a consumer of the stream, like {Manager#reset_consumer}.
      # @param name [String] Name of the consumer.
      # @param params [Hash] Options of {Manager#reset_consumer}, such as :seq.
      # @return [JetStream::API::ConsumerResetResponse]
      def reset_consumer(name, params = {})
        @js.reset_consumer(@name, name, params)
      end

      # consumers lists the info of the consumers of the stream, like
      # ListConsumers of nats.go.
      # @param params [Hash] Options to customize API request.
      # @return [Array<JetStream::API::ConsumerInfo>]
      def consumers(params = {})
        @js.consumers(@name, params)
      end
      alias_method :list_consumers, :consumers

      # consumer_names lists the names of the consumers of the stream, like
      # ConsumerNames of nats.go.
      # @param params [Hash] Options to customize API request.
      # @return [Array<String>]
      def consumer_names(params = {})
        @js.consumer_names(@name, params)
      end

      private

      def direct_get?
        !!@info&.config&.allow_direct
      end

      # push_config checks that the config of a push consumer delivers to
      # a subject, as nats.go does.
      def push_config(config)
        deliver_subject = config.is_a?(Hash) ? config[:deliver_subject] : config.deliver_subject
        raise Error::NotPushConsumer.new("nats: consumer is not a push consumer") if deliver_subject.to_s.empty?

        config
      end
    end
  end
end

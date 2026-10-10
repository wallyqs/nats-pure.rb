# frozen_string_literal: true

# Copyright 2025 The NATS Authors
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

module NATS
  class Service
    class Request < ::NATS::Msg
      attr_reader :error, :endpoint

      def initialize(opts = {})
        super
        @endpoint = opts[:endpoint]
        @error = nil
      end

      # Responds to the request, like Respond of nats.go micro. Unlike
      # NATS::Msg#respond, the response carries only the given headers,
      # not those of the request.
      #
      # @param data [String] The response payload.
      # @param headers [Hash] Headers of the response, like WithHeaders
      #   of nats.go micro.
      def respond(data = "", headers: nil)
        respond_msg(response(data, headers))
      end

      # Responds with obj as JSON, like RespondJSON of nats.go micro.
      #
      # @param obj [Object] The response, generated with JSON.generate.
      # @param headers [Hash] Headers of the response.
      # @raise [NATS::Service::MarshalResponseError] When obj cannot be
      #   generated as JSON, as for a NaN Float. Nothing is sent then.
      def respond_json(obj, headers: nil)
        json = begin
          JSON.generate(obj)
        rescue => e
          raise MarshalResponseError, "marshaling response: #{e.message}"
        end

        respond(json, headers: headers)
      end

      # Responds with a service error, like Error of nats.go micro.
      #
      # @param error [Exception, String, Hash] The error: an Exception or a
      #   String is a 500, a Hash gives its :code, :description and :data.
      # @param headers [Hash] Headers of the response, added to the error
      #   headers, which they can override, like WithHeaders of nats.go micro.
      def respond_with_error(error, headers: nil)
        @error = NATS::Service::ErrorWrapper.new(error)

        header = {
          "Nats-Service-Error" => @error.message,
          "Nats-Service-Error-Code" => @error.code
        }
        header.merge!(headers) if headers

        respond_msg(response(@error.data, header))
      end

      def inspect
        dot = "..." if @data.length > 10
        dat = "#{data.slice(0, 10)}#{dot}"
        "#<Service::Request(subject: \"#{@subject}\", reply: \"#{@reply}\", data: #{dat.inspect})>"
      end

      class << self
        def from_msg(svc, msg)
          request = Request.new(endpoint: svc)
          request.subject = msg.subject
          request.reply = msg.reply
          request.data = msg.data
          request.header = msg.header
          request.nc = msg.nc
          request.sub = msg.sub

          request
        end
      end

      private

      def response(data, header)
        ::NATS::Msg.new(subject: reply, reply: "", data: data, header: header, nc: nc)
      end
    end

    class Endpoint
      attr_reader :name, :service, :subject, :metadata, :queue, :stats

      def initialize(name:, options:, parent:, &block)
        validate(name, options)

        @name = name

        @service = parent.service
        @subject = build_subject(parent, options)
        @queue = options[:queue] || parent.queue
        @metadata = options[:metadata]

        @stats = NATS::Service::Stats.new
        @handler = create_handler(block)

        @stopped = false
      end

      def stop
        service.client.send(:drain_sub, @handler)
      rescue
        # nothing we can do here
      ensure
        @stopped = true
      end

      def reset
        stats.reset
      end

      # The subscription that receives the endpoint's requests.
      def subscription
        @handler
      end

      def stopped?
        @stopped
      end

      private

      def validate(name, options)
        Validator.validate(
          name: name,
          subject: options[:subject],
          queue: options[:queue]
        )
      end

      def build_subject(parent, options)
        subject = options[:subject] || name

        parent.subject ? "#{parent.subject}.#{subject}" : subject
      end

      def create_handler(block)
        service.client.subscribe(subject, queue: queue) do |msg|
          started_at = Time.now

          req = Request.from_msg(self, msg)
          block.call(req)
          stats.error(req.error) if req.error
        rescue NATS::Error => error
          # Passed to the error handler of the service, which stops, and
          # then to the client's error callback.
          service.send(:report_error, error, subject, self)
          raise error
        rescue => error
          stats.error(error)
          Request.from_msg(self, msg).respond_with_error(error)
        ensure
          stats.record(started_at)
        end
      rescue => error
        service.stop(error)
        raise error
      end
    end

    class Endpoints < NATS::Utils::List
      def add(name, options = {}, &block)
        endpoint = Endpoint.new(
          name: name,
          options: options,
          parent: parent,
          &block
        )

        insert(endpoint)
        parent.service.endpoints.insert(endpoint)

        endpoint
      end
    end
  end
end

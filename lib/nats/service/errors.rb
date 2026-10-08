# frozen_string_literal: true

module NATS
  class Service
    class Error < StandardError; end

    class InvalidNameError < Error; end

    class InvalidVersionError < Error; end

    class InvalidQueueError < Error; end

    class InvalidSubjectError < Error; end

    # When an endpoint is given a pending limit that is not a positive
    # Integer, like the ErrConfigValidation of WithEndpointPendingLimits of
    # nats.go micro.
    class InvalidPendingLimitsError < Error; end

    # When control_subject is given a verb other than :ping, :info and
    # :stats, like ErrVerbNotSupported of nats.go micro.
    class VerbNotSupportedError < Error; end

    # When control_subject is given a service id without a name, like
    # ErrServiceNameRequired of nats.go micro.
    class ServiceNameRequiredError < Error
      def initialize(msg = "service name is required to generate ID control subject")
        super
      end
    end

    # When respond_json cannot generate its response as JSON, like
    # ErrMarshalResponse of nats.go micro.
    class MarshalResponseError < Error; end

    # When a response cannot be sent, like ErrRespond of nats.go micro. Its
    # cause is the error of the client, such as
    # NATS::IO::ConnectionClosedError.
    class RespondError < Error; end

    # When respond_with_error is given an error without a code or a
    # description, like ErrArgRequired of nats.go micro.
    class ArgRequiredError < Error; end

    # NATSError is passed to the error handler of a service when one of the
    # service's subscriptions reports an asynchronous error, like a slow
    # consumer or a NATS error raised in an endpoint handler, like the
    # NATSError of nats.go micro. The subject links it to an endpoint, or to
    # a monitoring subject.
    class NATSError < Error
      attr_reader :subject, :description, :error

      def initialize(subject, description, error = nil)
        @subject = subject
        @description = description
        @error = error
        super("#{subject.inspect}: #{description}")
      end

      def ==(other)
        other.is_a?(NATSError) && subject == other.subject && description == other.description
      end
      alias_method :eql?, :==

      def hash
        [self.class, subject, description].hash
      end
    end

    class ErrorWrapper
      attr_reader :code, :message, :data

      def initialize(error)
        case error
        when Exception
          @code = 500
          # An error that has an empty message is named by its class.
          @message = error.message.empty? ? error.class.name : error.message
          @data = ""
        when Hash
          @code = error[:code]
          @message = error[:description]
          @data = error[:data]
        when ErrorWrapper
          @code = error.code
          @message = error.message
          @data = error.data
        else
          @code = 500
          @message = error.to_s
          @data = ""
        end
      end

      def description
        "#{code}:#{message}"
      end
    end
  end
end

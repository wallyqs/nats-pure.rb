# frozen_string_literal: true

require "monitor"

require_relative "service/group"
require_relative "service/endpoint"
require_relative "service/errors"

require_relative "service/validator"
require_relative "service/callbacks"
require_relative "service/monitoring"
require_relative "service/status"
require_relative "service/stats"

module NATS
  class Service
    include MonitorMixin

    DEFAULT_QUEUE = "q"

    attr_reader :client, :name, :id, :version, :description, :metadata, :queue
    attr_reader :monitoring, :status, :callbacks, :groups, :endpoints

    def initialize(client, options)
      super()
      validate(options)

      setup_options(options)
      setup_internals(client)
    end

    def on_stats(&block)
      callbacks.register(:stats, &block)
    end

    def on_stop(&block)
      callbacks.register(:stop, &block)
    end

    # Registers the error handler of the service, like the ErrorHandler of
    # nats.go micro, also set with the `:error_handler` option. It is called
    # with the service and a NATSError when one of the service's
    # subscriptions reports an asynchronous error, after which the service
    # stops.
    #
    # @example
    #   service.on_error do |service, error|
    #     puts "#{service.name} failed on #{error.subject}: #{error.description}"
    #   end
    def on_error(&block)
      callbacks.register(:error, &block)
    end

    def stopped?
      !!@stopped
    end

    def stop(error = nil)
      return if stopped?

      synchronize do
        monitoring&.stop
        endpoints&.each(&:stop)

        callbacks&.call(:stop, error)
      end
    ensure
      synchronize { @stopped = true }
    end

    def reset
      endpoints.each(&:reset)
    end

    def info
      status.info
    end

    def stats
      status.stats
    end

    def service
      self
    end

    def subject
      nil
    end

    private

    def validate(options)
      Validator.validate(options.slice(:name, :version, :queue))
    end

    def setup_options(options)
      @name = options[:name]
      @version = options[:version]
      @description = options[:description]
      @metadata = options[:metadata].freeze
      @queue = options[:queue] || DEFAULT_QUEUE
      @error_handler = options[:error_handler]
    end

    # Called by the client with the asynchronous errors of its
    # subscriptions. An error on one of the service's subscriptions is
    # passed to the error handler as a NATSError, is counted by the endpoint
    # it happened on, and stops the service, like nats.go micro does.
    def handle_async_error(error, sub)
      return if stopped?

      endpoint = endpoints.find { |e| e.subscription.equal?(sub) }
      return unless endpoint || monitoring.subscribed?(sub)

      report_error(error, sub.subject, endpoint)
    end

    def report_error(error, subject, endpoint = nil)
      return if stopped?

      begin
        callbacks.call(:error, self, NATSError.new(subject, error.message, error))
      ensure
        endpoint&.stats&.error(error)
        stop(error)
      end
    end

    def setup_internals(client)
      @client = client
      @id = NATS::NUID.next

      @callbacks = Callbacks.new(self)
      @callbacks.register(:error, &@error_handler) if @error_handler

      @monitoring = Monitoring.new(self)
      @status = Status.new(self)

      @groups = Groups.new(self)
      @endpoints = Endpoints.new(self)
    end
  end

  class Services < NATS::Utils::List
    attr_reader :client

    def initialize(client)
      @client = client
      super
    end

    def add(options)
      client.synchronize do
        service = NATS::Service.new(client, options)
        insert(service)

        service
      end
    end

    private

    # Called by the client with the asynchronous errors of its subscriptions.
    # An error raised by a callback must not break the client's thread that
    # reports the error.
    def handle_async_error(error, sub)
      to_a.each do |service|
        service.send(:handle_async_error, error, sub)
      rescue
        nil
      end
    end

    # Called by the client once its connection is closed: stops every
    # service, like nats.go micro does.
    def stop_all
      to_a.each do |service|
        service.stop
      rescue
        nil
      end
    end
  end
end

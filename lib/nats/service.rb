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

    # The root of all control subjects, like APIPrefix of nats.go micro.
    API_PREFIX = "$SRV"

    # The headers of an error response, like ErrorHeader and
    # ErrorCodeHeader of nats.go micro.
    ERROR_HEADER = "Nats-Service-Error"
    ERROR_CODE_HEADER = "Nats-Service-Error-Code"

    class << self
      # Returns a control subject of services, like ControlSubject of
      # nats.go micro: the subject to ping, or to get the info or stats of,
      # all services, the services named name, or the instance id of them.
      #
      # @example
      #   NATS::Service.control_subject(:ping)                  # => "$SRV.PING"
      #   NATS::Service.control_subject(:info, "calc")          # => "$SRV.INFO.calc"
      #   NATS::Service.control_subject(:stats, "calc", id)     # => "$SRV.STATS.calc.<id>"
      #
      # @param verb [Symbol, String] :ping, :info or :stats, in any case.
      # @param name [String, nil] The name of the services.
      # @param id [String, nil] The id of a service instance.
      # @raise [NATS::Service::VerbNotSupportedError] For any other verb.
      # @raise [NATS::Service::ServiceNameRequiredError] When id is given
      #   without a name.
      def control_subject(verb, name = nil, id = nil)
        verb_str = Monitoring::VERBS[verb.to_s.downcase.to_sym] if verb.is_a?(Symbol) || verb.is_a?(String)
        raise VerbNotSupportedError, "unsupported verb: #{verb.inspect}" unless verb_str

        name = nil if name.to_s.empty?
        id = nil if id.to_s.empty?
        raise ServiceNameRequiredError if name.nil? && id

        [API_PREFIX, verb_str, name, id].compact.join(".")
      end
    end

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
      # Like nats.go micro, services stop once their connection is closed.
      client.send(:add_status_listener) { |event| stop_all if event == :close }
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

    # Called once the connection of the client is closed: stops every
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

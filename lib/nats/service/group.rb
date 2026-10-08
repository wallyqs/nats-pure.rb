# frozen_string_literal: true

module NATS
  class Service
    class Group
      attr_reader :service, :name, :subject, :queue, :groups, :endpoints

      def initialize(name:, parent:, queue:, queue_group_disabled: false)
        Validator.validate(name: name, queue: queue)

        @name = name

        @service = parent.service
        @subject = parent.subject ? "#{parent.subject}.#{name}" : name
        @queue, @queue_group_disabled = Service.resolve_queue_group(
          queue, queue_group_disabled, parent.queue, parent.queue_group_disabled?
        )

        @groups = Groups.new(self)
        @endpoints = Endpoints.new(self)
      end

      # Whether the endpoints of the group, unless they say otherwise,
      # subscribe without a queue group, like WithGroupQueueGroupDisabled
      # of nats.go micro.
      def queue_group_disabled?
        @queue_group_disabled
      end
    end

    class Groups < NATS::Utils::List
      # Adds a group.
      #
      # @param name [String] The subject prefix of the group.
      # @param queue [String] The queue group of its endpoints.
      # @param queue_group_disabled [Boolean] Whether its endpoints
      #   subscribe without a queue group, like WithGroupQueueGroupDisabled
      #   of nats.go micro.
      def add(name, queue: nil, queue_group_disabled: false)
        group = Group.new(
          name: name,
          queue: queue,
          queue_group_disabled: queue_group_disabled,
          parent: parent
        )

        insert(group)
        parent.service.groups.insert(group)

        group
      end
    end
  end
end

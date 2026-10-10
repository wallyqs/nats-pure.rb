# Service API

Service API provides a simple way to create microservices that leverage NATS for scalability, load management, and observability. The Service API allows your services 
to be discovered, queried for status and schema information without additional work.

- [Service](#service)
- [Endpoints](#endpoints)
- [Groups](#groups)
- [Service Lifecycle](#service-lifecycle)
- [Error Handling](#error-handling)
- [Stats](#stats)
- [Discovery and Monitoring](#discovery-and-monitoring)
- [Examples](#examples)

## Service

The core of the Service API is a service. It encapsulates the application logic, collects statistics, and provides additional info.

You can create a service with:

```ruby
client = NATS.connect
service = client.services.add(options)
```

The options are:

- `:name` - the kind of a service. Multiple services can have the same name. 
This name can only contain A-Z, a-z, 0-9, dash, and underscore.
- `:version` - a service version in the form of a SemVer string.
- `:description` (optional) - a human-readable description about a service.
- `:metadata` (optional) - a hash that holds additional information about a service.
- `:queue` (optional) - a queue group.
- `:error_handler` (optional) - a callable that receives the service and a
`NATS::Service::NATSError` when one of the service's subscriptions fails (see [Service Lifecycle](#service-lifecycle)).

While multiple service instances can share the same name, each service has a unique id that is generated upon its creation:

```ruby
client = NATS.connect

service = client.services.add(
  name: "calc",
  version: "1.0.0"
)

service.id
# ZrhOTJwPyGeHhM6K257pwl
```

## Endpoints

An endpoint encapsulates the service logic and creates a subscription to handle the requests:

```ruby
service.endpoints.add(name, options) do |message|
  ...
end
```

`name` is an alphanumeric human-readable string that describes the endpoint. Multiple endpoints can have the same names. 

Options can contain:
- `:subject` (optional) - an optional NATS subject on which the endpoint will be registered. Defaults to `name`.
- `:metadata` (optional) - a hash containing additional information about an endpoint.
- `:queue` (optional) - an override for a service and group.

After creating an endpoint you can publish a request on its subject:

```ruby
service.endpoints.add("hi") do |message|
  message.respond("Hi!")
end

client.request("hi")
# Hi!
```

`respond_json` responds with an object as JSON. An object that cannot be generated as JSON,
like a NaN Float, raises `NATS::Service::MarshalResponseError`, and nothing is sent:

```ruby
service.endpoints.add("hi") do |message|
  message.respond_json({greeting: "Hi!"})
end

client.request("hi")
# {"greeting":"Hi!"}
```

`respond`, `respond_json` and `respond_with_error` take `headers:` for the response.
The response carries only those headers, not the headers of the request:

```ruby
service.endpoints.add("hi") do |message|
  message.respond("Hi!", headers: {"Content-Language" => "en"})
end

client.request("hi").header
# {"Content-Language"=>"en"}
```

You can also create multiple endpoints:

```ruby
client = NATS.connect

service = client.services.add(
  name: "calc",
  version: "1.0.0"
)

service.endpoints.add("min") do |message|
  min = JSON.parse(message.data).min
  message.respond(min.to_json)
end

service.endpoints.add("max") do |message|
  max = JSON.parse(message.data).max
  message.respond(max.to_json)
end

min = client.request("min", [5, 100, -7, 34].to_json)
max = client.request("max", [5, 100, -7, 34].to_json)
```

## Groups

Endpoints can be aggregated using groups. A group represents a common
subject prefix used by all endpoints associated with it.

```ruby
group = service.groups(name)
```

The name can be anything that is a valid subject prefix. You can pass a queue 
to a group that will be used for all its endpoints:

```ruby
group = service.groups(name, queue: "queue")
```

When you add an endpoint to a group, the endpoint is registered on the subject 
created by concatenating the group name and the endpoint subject:

```ruby
group = service.groups("numbers")

group.endpoints.add("sum") do |message|
  sum = JSON.parse(message.data).sum
  message.respond(sum.to_json)
end

client.request("numbers.sum", [1, 2, 3, 4].to_json)
```

You can build a subject hierarchy for your services by creating nested groups:

```ruby
numbers = service.groups.add("numbers")
aggregation = numbers.groups.add("agg")

aggregation.endpoints.add("avg") do |message|
  data = JSON.parse(message.data)
  avg = data.sum / data.size.to_f

  message.respond(avg.to_json)
end

client.request("numbers.agg.avg", [3, 4, 5, 7].to_json)
```

## Service Lifecycle

Every time you create a service or add endpoints to an already existing service, 
a few subscriptions are created under the hood to handle the service's internal work.
If your service finishes its job, you can stop it and drain all its subscriptions with:

```ruby
service.stop
```

The service is automatically stopped whenever a NATS-related error occurs during service work,
like a `NATS::Error` raised in an endpoint or a slow consumer on one of the service's subscriptions,
and when its connection is closed.
You can use `on_stop` callback to handle the error and gracefully finish the service work:

```ruby
service.on_stop do |error|
  puts "Server stopped due to #{error.message}"
end

service.endpoints.add("error") do |message|
  raise NATS::IO::ServerError
end

client.request("error")
# Server stopped due to NATS::IO::ServerError
```

Before the service stops on an error, its error handler, set with the `:error_handler`
option or with `on_error`, receives the service and a `NATS::Service::NATSError`, which
names the `subject` of the failed subscription and the `description` of the error
(the original exception is its `error`). The error is also counted in the stats of the
endpoint, and passed on to the client's `on_error` callback:

```ruby
service.on_error do |service, error|
  puts "#{service.name} failed on #{error.subject}: #{error.description}"
end
```

Errors on subscriptions that are not the service's are left to the client.

## Error Handling

If an error occurs in an endpoint, the service will communicate request errors 
back to the client with the headers `Nats-Service-Error` and `Nats-Service-Error-Code`,
named by `NATS::Service::ERROR_HEADER` and `NATS::Service::ERROR_CODE_HEADER`:

```ruby
service.endpoints.add("divide") do |message|
  dividend, divisor = JSON.parse(message.data)
  message.respond((dividend / divisor).to_json)
end

client.request("divide", [5, 0].to_json)
# NATS::Msg(reply: "", data: "", header={"Nats-Service-Error"=>"divided by 0", "Nats-Service-Error-Code"=>"500"})
```

You can also manually send an error message with `respond_with_error` method:

```ruby
service.endpoints.add("divide") do |message|
  dividend, divisor = JSON.parse(message.data)

  if divisor.zero?
    message.respond_with_error("It's impossible to divide by zero")
  else
    message.respond((dividend / divisor).to_json)
  end
end

client.request("divide", [5, 0].to_json)
# NATS::Msg(reply: "", data: "", header={"Nats-Service-Error"=>"It's impossible to divide by zero", "Nats-Service-Error-Code"=>"500"})
```

Headers given to `respond_with_error` with `headers:` are added to the error headers,
and can override them.

## Stats

A service collects different stats during its work, which you can access via `stats` method:

```ruby
{
  name: string,
  id: string,
  version: string,
  metadata: hash,
  started: string # ISO Date string when the service started in UTC timezone
  endpoints: [
    {
      name: string, # The name of the endpoint
      subject: string, # The subject on which the endpoint is listening
      queue_group: string, # Queue group to which this endpoint is assigned to
      num_requests: number, # The number of requests received by the endpoint
      num_errors: number, # Number of errors that the endpoint has raised
      last_error: string, # If set, the last error triggered by the endpoint
      data: object, # A field that can be customized with any data as returned by on_stats callback
      processing_time: integer, # Total processing time for the service in nanoseconds
      average_processing_time: integer, # Average processing time in nanoseconds
    }
  ]
}
```

You can define `on_stats` callback to add additional metrics to stats:

```ruby
service.on_stats do |endpoint|
  { object_id: endpoint.object_id }
end

service.endpoints.add("sum") do |message|
  ...
end

service.stats
# {
#   :name=>"calc",
#   :id=>"ZrhOTJwPyGeHhM6K257pwl",
#   :version=>"1.0.0",
#   :metadata=>nil,
#   :started=>"2025-01-01T15:47:14Z",
#   :endpoints=>[
#     {
#       :name=>"sum",
#       :subject=>"divide",
#       :queue_group=>"q",
#       :num_requests=>1,
#       :processing_time=>34000,
#       :average_processing_time=>34000,
#       :num_errors=>0,
#       :last_error=>"",
#       :data=>{:object_id=>26980}
#     }
#   ]
# }
```

## Discovery and Monitoring

Using the specified name and automatically generated id, the service automatically 
creates subscriptions to handle discovery and monitoring requests. The subject for 
discovery and requests is prefixed by `$SRV` with the following verbs:

- `PING` - used for service discovery and RTT calculation
- `INFO` returns service configuration details (used subjects, service metadata, etc.)
- `STATS` - service statistics

Each of those operations can be performed on three subjects:

- `$SRV.PING|STATS|INFO` - pings and retrieves status for all services 
- `$SRV.PING|STATS|INFO.<name>` - pings or retrieves status for all services having the specified name 
- `$SRV.PING|STATS|INFO.<name>.<id>` - pings or retrieves status of a particular service instance

`NATS::Service.control_subject(verb, name = nil, id = nil)` builds these subjects, for the
verbs `:ping`, `:info` and `:stats`. Another verb raises `NATS::Service::VerbNotSupportedError`,
and an id without a name raises `NATS::Service::ServiceNameRequiredError`:

```ruby
NATS::Service.control_subject(:ping)                    # "$SRV.PING"
NATS::Service.control_subject(:info, "calc")            # "$SRV.INFO.calc"
NATS::Service.control_subject(:stats, "calc", service.id)
```

```ruby
service = client.services.add(
  name: "calc",
  version: "1.0.0"
)

client.request("$SRV.PING.calc")
client.request("$SRV.INFO.calc")
client.request("$SRV.STATS.calc")
```

## Examples

For more examples, refer to [examples/service_api](../examples/service_api) directory.

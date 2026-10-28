# Copyright 2016-2018 The NATS Authors
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
# Property based tests, none of these need a running server.
#
require 'spec_helper'
require 'json'

begin
  require 'zizek/rspec'
rescue LoadError
  # The zizek gem requires Ruby >= 2.6, skip the properties otherwise.
end

if defined?(Zizek)

  module Props
    G = Zizek::Generators
    SUBJECT_ALPHABET = "abcxyz019.*>_-"
    PRINTABLE = Zizek.alphabet_range(0x20, 0x7E)
    DIGITS = NATS::NUID::DIGITS.join
    HOST = G.sampled_from(%w[a.example b.example 10.0.0.1 10.0.0.2 [::1] [fe80::1]])
    PORT = G.sampled_from([4222, 4223, 4224])
    URLS = G.lists(G.tuples(HOST, PORT).map { |h, p| "#{h}:#{p}" }, min: 0, max: 8)
    PUB = /\APUB (\S+) (\S*) (\d+)\r\n(.*)\r\n\z/m

    # Records what the parser hands to the client.
    class Recorder
      attr_reader :events

      def initialize
        @events = []
      end

      def process_msg(subject, sid, reply, data)
        @events << [:msg, subject, sid, reply, data.b]
      end

      def process_err(err)
        @events << [:err, err]
      end

      def process_ping
        @events << [:ping]
      end

      def process_pong
        @events << [:pong]
      end

      def process_info(line)
        @events << [:info, line]
      end
    end

    # IO stub for the connect handshake.
    class FakeIO
      attr_reader :written

      def initialize(lines)
        @lines = lines
        @written = []
      end

      def read_line(_deadline=nil)
        @lines.shift
      end

      def write(data, _deadline=nil)
        @written << data
      end

      def closed?
        false
      end
    end

    # Client with the state of a connected one but without any sockets or threads.
    def self.client
      nc = NATS::IO::Client.new
      nc.instance_variable_set(:@pending_queue, [])
      nc.instance_variable_set(:@flush_queue, [])
      nc.instance_variable_set(:@options, {
        user: nil, pass: nil, verbose: false, pedantic: false, connect_timeout: 1
      })
      nc.instance_variable_set(:@uri, URI.parse("nats://127.0.0.1:4222"))
      nc.instance_variable_set(:@status, NATS::IO::CONNECTED)
      nc
    end

    def self.subs_of(nc)
      nc.instance_variable_get(:@subs)
    end

    # Every subscription created, including the ones removed right away.
    def self.created_subscriptions
      @created_subscriptions ||= []
    end

    module TrackSubscriptions
      def initialize(*args)
        super
        Props.created_subscriptions << self
      end
    end
    NATS::Subscription.send(:prepend, TrackSubscriptions)

    def self.pending_commands(nc)
      nc.instance_variable_get(:@pending_queue)
    end

    # Wire ops a server could send, with the events the parser should produce.
    SUBJECT = G.text(min: 1, max: 8, alphabet: SUBJECT_ALPHABET)
    SID     = G.integers(1..999)
    PAYLOAD = G.binary(min: 0, max: 24)
    OP = G.one_of(
      G.tuples(G.just(:msg), SUBJECT, SID, G.just(nil) | SUBJECT, PAYLOAD),
      G.just([:ping]),
      G.just([:pong]),
      G.just([:ok]),
      G.tuples(G.just(:err), G.text(min: 1, max: 12, alphabet: "abc xyz\"")),
      G.tuples(G.just(:info), G.text(min: 1, max: 8, alphabet: "abc01"))
    )

    def self.encode_op(op)
      case op[0]
      when :msg
        _, subj, sid, reply, data = op
        line = if reply
                 "MSG #{subj} #{sid} #{reply} #{data.bytesize}\r\n"
               else
                 "MSG #{subj} #{sid} #{data.bytesize}\r\n"
               end
        [line.b + data.b + "\r\n".b, [:msg, subj, sid, reply, data.b]]
      when :ping then ["PING\r\n".b, [:ping]]
      when :pong then ["PONG\r\n".b, [:pong]]
      when :ok   then ["+OK\r\n".b, nil]
      when :err  then ["-ERR '#{op[1]}'\r\n".b, [:err, "'#{op[1]}'"]]
      when :info
        json = { "server_id" => op[1] }.to_json
        ["INFO #{json}\r\n".b, [:info, json]]
      end
    end

    # Splits the wire bytes at the given positions.
    def self.chunk(wire, cuts)
      cuts = cuts.map { |c| c % (wire.bytesize + 1) }.uniq.sort
      pieces = []
      prev = 0
      (cuts + [wire.bytesize]).each do |c|
        next if c <= prev
        pieces << wire.byteslice(prev, c - prev)
        prev = c
      end
      pieces << wire.byteslice(prev..-1) if prev < wire.bytesize
      pieces
    end

    # Drives subscribe/unsubscribe/process_msg against a model of what
    # the client should deliver to the callbacks.
    class SubscriptionMachine < Zizek::Stateful::Machine
      def initialize
        @nc = Props.client
        @model = {}          # sid => { max:, received:, delivered:, active: }
        @seen = Hash.new(0)  # sid => callback deliveries
        @seen_mutex = Mutex.new
        @subs = {}           # sid => NATS::Subscription
      end

      def existing_sid(tc)
        tc.assume(!@model.empty?)
        tc.draw(G.sampled_from(@model.keys), name: :sid)
      end

      rule(:subscribe) do |tc|
        max = tc.draw(G.just(nil) | G.integers(0..4), name: :max)
        opts = {}
        opts[:max] = max if max
        sid = @nc.subscribe("foo", opts) { |_m| @seen_mutex.synchronize { @seen[sid] += 1 } }
        @subs[sid] = Props.created_subscriptions.last
        @model[sid] = { max: max, received: 0, delivered: 0, active: max.nil? || max > 0 }
      end

      rule(:unsubscribe) do |tc|
        sid = existing_sid(tc)
        max = tc.draw(G.just(nil) | G.integers(0..4), name: :max)
        @nc.unsubscribe(sid, max)
        m = @model[sid]
        m[:max] = max
        m[:active] = false unless max && m[:received] < max
      end

      rule(:deliver) do |tc|
        sid = existing_sid(tc)
        data = tc.draw(G.binary(min: 0, max: 8), name: :data)
        @nc.process_msg("foo", sid, nil, data)
        m = @model[sid]
        if m[:active]
          m[:received] += 1
          if m[:max] && m[:received] > m[:max]
            m[:active] = false
          else
            m[:delivered] += 1
            m[:active] = false if m[:max] && m[:received] == m[:max]
          end
        end
      end

      rule(:deliver_unknown_sid) do |tc|
        sid = tc.draw(G.integers(10_000..10_010), name: :sid)
        @nc.process_msg("foo", sid, nil, "x")
      end

      invariant(:registered_sids_match_model) do
        active = @model.select { |_, m| m[:active] }.keys.sort
        registered = Props.subs_of(@nc).keys.sort
        raise "registered #{registered.inspect} but model active #{active.inspect}" unless registered == active
      end

      invariant(:callback_deliveries_match_model) do
        wait_until(0.5) { @model.all? { |sid, m| seen(sid) == m[:delivered] } }
        @model.each do |sid, m|
          next if seen(sid) == m[:delivered]
          raise "sid #{sid}: callback ran #{seen(sid)} times, model says #{m[:delivered]} (max=#{m[:max].inspect})"
        end
      end

      invariant(:no_delivery_thread_outlives_its_subscription) do
        inactive = @model.reject { |_, m| m[:active] }.keys
        wait_until(0.5) { inactive.none? { |sid| @subs[sid].wait_for_msgs_t.alive? } }
        inactive.each do |sid|
          next unless @subs[sid].wait_for_msgs_t.alive?
          raise "sid #{sid} is no longer subscribed but its delivery thread is still alive"
        end
      end

      def seen(sid)
        @seen_mutex.synchronize { @seen[sid] }
      end

      def wait_until(timeout)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        until yield
          break if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
          sleep 0.001
        end
      end
    end
  end

  G = Props::G

  describe 'Protocol parser properties' do
    property "output does not depend on how the stream is chunked",
             ops: G.lists(Props::OP, min: 1, max: 6),
             cuts: G.lists(G.integers(0..300), max: 8),
             settings: { examples: 300, seed: 21 } do |ops, cuts|
      encoded = ops.map { |op| Props.encode_op(op) }
      wire = encoded.map(&:first).join.b
      expected = encoded.map(&:last).compact
      rec = Props::Recorder.new
      parser = NATS::Protocol::Parser.new(rec)
      Props.chunk(wire, cuts).each { |piece| parser.parse(piece.dup) }
      expect(rec.events).to eql(expected)
    end

    property "never raises on arbitrary bytes and recovers at the next complete line",
             junk: G.binary(min: 0, max: 40),
             cuts: G.lists(G.integers(0..60), max: 4),
             settings: { examples: 300, seed: 23 } do |junk, cuts|
      rec = Props::Recorder.new
      parser = NATS::Protocol::Parser.new(rec)
      wire = junk + "\r\nPING\r\n".b
      Props.chunk(wire, cuts).each { |piece| parser.parse(piece.dup) }

      # Unless the junk looked like the start of a MSG and the parser is now
      # rightfully waiting for its payload, the PING must have been seen.
      awaiting_payload = parser.instance_variable_get(:@parse_state) == NATS::Protocol::AWAITING_MSG_PAYLOAD
      unless awaiting_payload || rec.events.any? { |e| e[0] == :msg }
        expect(rec.events.last).to eql([:ping])
      end
    end
  end

  describe 'NUID properties' do
    property "yields 22 char base62 ids which are unique and increasing within a prefix",
             n: G.integers(1..500), settings: { examples: 50, seed: 31 } do |n|
      nuid = NATS::NUID.new
      ids = Array.new(n) { nuid.next }
      ids.each do |id|
        expect(id.size).to eql(22)
        expect(id.chars.all? { |c| Props::DIGITS.include?(c) }).to be(true)
      end
      expect(ids.uniq.size).to eql(n)
      ids.each_cons(2) do |a, b|
        expect(b > a).to be(true) if a[0, 12] == b[0, 12]
      end
    end

    property "stays well formed across a sequence wrap",
             gap: G.integers(0..1000), inc: G.integers(33..332), calls: G.integers(1..20),
             settings: { examples: 100, seed: 32 } do |gap, inc, calls|
      nuid = NATS::NUID.new
      nuid.instance_variable_set(:@seq, NATS::NUID::MAX_SEQ - gap)
      nuid.instance_variable_set(:@inc, inc)
      ids = Array.new(calls) { nuid.next }
      ids.each do |id|
        expect(id.size).to eql(22)
        expect(id.chars.all? { |c| Props::DIGITS.include?(c) }).to be(true)
      end
      expect(ids.uniq.size).to eql(calls)
      expect(nuid.instance_variable_get(:@seq)).to be < NATS::NUID::MAX_SEQ
    end
  end

  describe 'Client properties' do
    describe 'server discovery' do
      property "never adds duplicate servers nor the current one to the pool",
               batches: G.lists(Props::URLS, min: 1, max: 3), settings: { examples: 200, seed: 41 } do |batches|
        nc = Props.client
        nc.instance_variable_set(:@uri, URI.parse("nats://a.example:4222"))
        nc.instance_variable_set(:@options, { dont_randomize_servers: true })
        nc.server_pool << { uri: nc.uri, was_connected: true }

        batches.each do |urls|
          nc.process_info({ "server_id" => "x", "connect_urls" => urls }.to_json)
        end

        keys = nc.server_pool.map { |s| [s[:uri].host, s[:uri].port] }
        expect(keys.uniq).to eql(keys)
        announced = batches.flatten.map { |u| URI.parse("nats://#{u}") }.map { |u| [u.host, u.port] }
        expect(keys.sort).to eql((announced << ["a.example", 4222]).uniq.sort)
      end
    end

    describe 'publish framing' do
      property "emits a single well formed PUB or rejects the subject",
               subject: G.text(min: 1, max: 8, alphabet: Props::SUBJECT_ALPHABET + " \t\r\n"),
               reply: G.just(nil) | G.text(min: 1, max: 8, alphabet: Props::SUBJECT_ALPHABET + " \t\r\n"),
               msg: G.binary(min: 0, max: 16),
               settings: { examples: 300, seed: 51 } do |subject, reply, msg|
        nc = Props.client
        begin
          nc.publish(subject, msg, reply)
        rescue NATS::IO::BadSubject
          expect(Props.pending_commands(nc)).to be_empty
          next
        end

        m = Props::PUB.match(Props.pending_commands(nc).last)
        expect(m).not_to be_nil
        expect(m[1]).to eql(subject)
        expect(m[2].empty? ? nil : m[2]).to eql(reply)
        expect(m[3].to_i).to eql(msg.bytesize)
        expect(m[4].b).to eql(msg.b)
      end

      property "subscribe rejects subjects which would break the framing",
               subject: G.text(min: 0, max: 8, alphabet: Props::SUBJECT_ALPHABET + " \t\r\n"),
               settings: { examples: 200, seed: 54 } do |subject|
        nc = Props.client
        if subject.empty? || subject =~ /\s/
          expect { nc.subscribe(subject) { } }.to raise_error(NATS::IO::BadSubject)
          expect(Props.subs_of(nc)).to be_empty
        else
          sid = nc.subscribe(subject) { }
          expect(Props.pending_commands(nc).last).to eql("SUB #{subject}  #{sid}\r\n")
          nc.unsubscribe(sid)
        end
      end
    end

    describe 'credentials' do
      property "given as connect options reach the CONNECT line unchanged",
               user: G.text(min: 1, max: 8, alphabet: Props::PRINTABLE),
               pass: G.text(min: 1, max: 8, alphabet: Props::PRINTABLE),
               settings: { examples: 200, seed: 52 } do |user, pass|
        nc = Props.client
        nc.options.merge!(user: user, pass: pass)
        nc.server_pool << { uri: URI.parse("nats://127.0.0.1:4222") }
        nc.send(:select_next_server)

        line = nc.send(:connect_command)
        expect(line.scan("\r\n").size).to eql(1)
        cs = JSON.parse(line.sub(/\ACONNECT /, ""))
        expect(cs["user"]).to eql(user)
        expect(cs["pass"]).to eql(pass)
      end

      property "percent-encoded in a server URL are decoded before CONNECT",
               user: G.text(min: 1, max: 8, alphabet: Props::PRINTABLE),
               pass: G.text(min: 1, max: 8, alphabet: Props::PRINTABLE),
               settings: { examples: 200, seed: 53 } do |user, pass|
        nc = Props.client
        enc = lambda { |s| URI.encode_www_form_component(s).gsub("+", "%20") }
        nc.server_pool << { uri: URI.parse("nats://#{enc[user]}:#{enc[pass]}@127.0.0.1:4222") }
        nc.send(:select_next_server)

        cs = JSON.parse(nc.send(:connect_command).sub(/\ACONNECT /, ""))
        expect(cs["user"]).to eql(user)
        expect(cs["pass"]).to eql(pass)
      end
    end

    describe 'connect handshake' do
      property "accepts any JSON INFO the server could send",
               server_id: G.text(min: 1, max: 10, alphabet: Props::PRINTABLE),
               version: G.text(min: 1, max: 10, alphabet: Props::PRINTABLE),
               max_payload: G.integers(0..10_000_000),
               settings: { examples: 200, seed: 61 } do |server_id, version, max_payload|
        nc = Props.client
        info = { "server_id" => server_id, "version" => version, "max_payload" => max_payload }
        nc.instance_variable_set(:@io, Props::FakeIO.new(["INFO #{info.to_json}\r\n", "PONG\r\n"]))
        nc.send(:process_connect_init)
        expect(nc.server_info[:server_id]).to eql(server_id)
        expect(nc.server_info[:version]).to eql(version)
        expect(nc.server_info[:max_payload]).to eql(max_payload)
      end
    end

    describe 'subscriptions' do
      it "deliver, auto unsubscribe and stop their threads as modeled" do
        Zizek.check(Props::SubscriptionMachine.property(step_count: 15), examples: 100, seed: 71)
      end
    end

    describe 'requests' do
      property "which time out leave nothing behind in the responses map",
               n: G.integers(1..10), settings: { examples: 20, seed: 81 } do |n|
        nc = Props.client
        n.times do
          expect { nc.request("foo", "bar", timeout: 0.001) }.to raise_error(NATS::IO::Timeout)
        end
        expect(nc.instance_variable_get(:@resp_map)).to be_empty
      end
    end
  end
end

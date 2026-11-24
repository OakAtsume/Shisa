# frozen_string_literal: true

# Skeleton: event-driven Diffie server with JSON event dispatch.
#
#   ruby examples/protocol_server.rb [port]      (default 8081)
#
# Mirrors the Crystal protocol_client.cr design. The three layers:
#
#   Transport   SocketServer + Diffie::Session + FrameParser  (transport.rb)
#   Protocol    Envelope (JSON) + Dispatcher (event -> handler)
#   Handlers    hello, heartbeat, sysinfo, message, ...  (you add these)
#
# Adding a new event is: define the handler, register it, done.
require "json"
require_relative "transport"

# =============================================================================
# Protocol layer: envelope + dispatcher
# =============================================================================

# Every message on the wire is a JSON envelope. The `event` field decides
# which handler runs; `payload` carries event-specific data; `id` is an
# optional correlation token for request/reply pairs.
module Protocol
  Envelope = Struct.new(:event, :id, :payload, keyword_init: true) do
    def self.from_json(raw)
      data = JSON.parse(raw, symbolize_names: true)
      new(
        event:  data[:event],
        id:      data[:id],
        payload: data[:payload]
      )
    end

    def to_json(*)
      hash = { event: event }
      hash[:id]      = id      if id
      hash[:payload] = payload if payload
      hash.to_json
    end
  end

  # Routes decoded envelopes to registered handlers by event name.
  # Unknown events go to the fallback (logged, not crashed), so the two
  # sides can evolve independently.
  class Dispatcher
    def initialize
      @handlers = Hash.new { |h, k| h[k] = [] }
      @fallback = nil
    end

    # Register a handler for an event. Multiple handlers per event run
    # in registration order.
    def on(event, &block)
      @handlers[event.to_s] << block
    end

    # Called for any event with no registered handler.
    def on_unhandled(&block)
      @fallback = block
    end

    # Parse raw decrypted string as an Envelope and dispatch.
    # +client_id+ and +server+ are passed through so handlers can reply.
    def dispatch(client_id, server, raw)
      env = Envelope.from_json(raw)
      list = @handlers[env.event]
      if list && !list.empty?
        list.each { |h| h.call(client_id, server, env) }
      elsif @fallback
        @fallback.call(client_id, server, env)
      end
    rescue JSON::ParserError
      # Not every message is JSON yet (e.g. a plain-text legacy client).
      # Log it and carry on.
      $stderr.puts "[dispatch] not JSON from #{client_id}: #{raw.to_s.encode('UTF-8', invalid: :replace, undef: :replace, replace: '?')[0, 120]}"
    end
  end
end

# =============================================================================
# ProtocolServer: wires transport + dispatcher together
# =============================================================================

class ProtocolServer
  attr_reader :dispatcher, :transport

  def initialize(port)
    @transport  = SocketServer.new(port)
    @dispatcher = Protocol::Dispatcher.new

    wire_transport_events
  end

  # Register an event handler directly on the server for convenience.
  def on(event, &block)
    @dispatcher.on(event, &block)
  end

  def on_unhandled(&block)
    @dispatcher.on_unhandled(&block)
  end

  # Send a structured Envelope to one client.
  def send_envelope(client_id, env)
    @transport.write(client_id, env.to_json)
  end

  # Shorthand: send an event with no payload.
  def send_event(client_id, event)
    send_envelope(client_id, Protocol::Envelope.new(event: event))
  end

  # Shorthand: send an event with a payload hash.
  def send_eventPayload(client_id, event, payload)
    send_envelope(client_id, Protocol::Envelope.new(event: event, payload: payload))
  end

  # Broadcast an envelope to every connected client.
  def broadcast(env)
    ids = @transport.clients.keys
    ids.count { |id| send_envelope(id, env) }
  end

  # Broadcast an event with optional payload.
  def broadcast_event(event, payload = nil)
    broadcast(Protocol::Envelope.new(event: event, payload: payload))
  end

  def clients
    @transport.clients
  end

  def disconnect(client_id)
    @transport.disconnect(client_id)
  end

  def start
    @transport.start
  end

  private

  def wire_transport_events
    # Route every decrypted message through the dispatcher.
    @transport.on(:onMessage) do |client_id, _socket, raw|
      @dispatcher.dispatch(client_id, self, raw)
    end

    # Transport-level events are still available through the dispatcher
    # as pseudo-events, so handlers can react to connect/disconnect the
    # same way they react to protocol messages.
    @transport.on(:onConnect) do |client_id, _socket|
      @dispatcher.dispatch(client_id, self,
        Protocol::Envelope.new(event: "_connect").to_json)
    end

    @transport.on(:onDisconnect) do |client_id, _socket|
      @dispatcher.dispatch(client_id, self,
        Protocol::Envelope.new(event: "_disconnect").to_json)
    end

    @transport.on(:onProtocolError) do |client_id, _socket, error_id, message|
      say "[PROTOCOL-ERROR] #{client_id} (#{error_id}): #{message}"
    end

    @transport.on(:onHandshakeError) do |host, error_id, message|
      say "[HANDSHAKE-ERROR] #{host} (#{error_id}): #{message}"
    end
  end
end

# =============================================================================
# Helpers
# =============================================================================

$stdout.sync = true
$current_prompt = "> "

def say(line)
  print("\r\e[K#{line}\n#{$current_prompt}")
end

def resolve(server, id)
  ids = server.clients.keys
  return id if ids.include?(id)

  matches = ids.select { |c| c.start_with?(id) }
  case matches.size
  when 1 then matches.first
  when 0 then (puts("no client matching '#{id}'"); nil)
  else (puts("ambiguous id '#{id}': #{matches.join(', ')}"); nil)
  end
end

# =============================================================================
# Handlers: register as many as you need
# =============================================================================

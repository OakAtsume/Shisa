# frozen_string_literal: true

require "minitest/autorun"
require "minitest/pride"
require "tempfile"
require "ostruct"

# Add project root to load path
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), "..", "src"))

# Minimal server mock that satisfies Shell and TunnelManager initialization.
class MockServer
  attr_reader :clients, :handlers, :sent

  def initialize
    @clients  = {}
    @handlers = {}
    @sent     = []
  end

  def on(event, &block)
    @handlers[event] = block
  end

  def send_envelope(client_id, envelope)
    @sent << { client_id: client_id, envelope: envelope }
  end

  def send_event(client_id, event, payload = nil)
    @sent << { client_id: client_id, event: event, payload: payload }
  end

  def broadcast_event(event, payload = nil)
    @clients.size
  end

  def disconnect(client_id)
    @clients.delete(client_id)
  end

  # Simulate dispatching an event through registered handlers.
  def dispatch(event, client_id, env)
    handler = @handlers[event]
    handler&.call(client_id, self, env)
  end
end

require "spec"
require "json"
require "base64"

require "../src/protocol"

# Test double for ProtocolClient — captures all sent envelopes.
class ProtocolClient
  getter sent : Array(Envelope)
  getter dispatcher : Dispatcher

  def initialize
    @sent = [] of Envelope
    @dispatcher = Dispatcher.new
  end

  def on(action : String, &block : Dispatcher::Handler)
    @dispatcher.on(action, &block)
  end

  def on_unhandled(&block : Dispatcher::Handler)
    @dispatcher.on_unhandled(&block)
  end

  def send(env : Envelope) : Nil
    @sent << env
  end

  def send(action : String) : Nil
    @sent << Envelope.new(action)
  end

  def send(action : String, payload : Hash(String, String)) : Nil
    wrapped = payload.transform_values { |v| JSON::Any.new(v) }
    @sent << Envelope.new(action, payload: JSON::Any.new(wrapped))
  end

  def disconnect : Nil
  end

  def running? : Bool
    false
  end

  def last_sent : Envelope
    @sent.last
  end

  def last_payload : JSON::Any
    @sent.last.payload.not_nil!
  end

  def clear!
    @sent.clear
  end

  # Dispatch an event as if it arrived from the network.
  def inject(event : String, id : String? = nil, payload : JSON::Any? = nil)
    env = Envelope.new(event, id, payload)
    @dispatcher.dispatch(env.to_json.to_slice)
  end
end

require "../src/handlers/commands"

# Build a JSON::Any payload from a hash.
def build_payload(hash : Hash(String, String)) : JSON::Any
  JSON::Any.new(hash.transform_values { |v| JSON::Any.new(v) })
end

def build_payload(**kwargs) : JSON::Any
  h = {} of String => JSON::Any
  kwargs.each { |k, v| h[k.to_s] = JSON::Any.new(v) }
  JSON::Any.new(h)
end

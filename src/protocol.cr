require "json"

struct Envelope
  include JSON::Serializable
  property event : String
  property id : String? = nil
  property payload : JSON::Any? = nil

  def initialize(@event, @id = nil, @payload = nil)
  end
end

class Dispatcher
  alias Handler = Envelope ->

  @handlers = {} of String => Array(Handler)
  @fallback : Handler? = nil

  def initialize
  end

  def on(action : String, &block : Handler)
    (@handlers[action] ||= [] of Handler) << block
  end

  def on_unhandled(&block : Handler)
    @fallback = block
  end

  def dispatch(raw : Bytes) : Nil
    env = Envelope.from_json(String.new(raw))
    if list = @handlers[env.event]?
      list.each &.call(env)
    elsif fb = @fallback
      fb.call(env)
    end
  rescue ex : JSON::ParseException
    STDERR.puts "[dispatch] not JSON: #{String.new(raw)}"
  end
end

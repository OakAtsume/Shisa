require "./spec_helper"

describe Envelope do
  describe "serialization" do
    it "round-trips event-only envelope" do
      env = Envelope.new("ping")
      parsed = Envelope.from_json(env.to_json)
      parsed.event.should eq("ping")
      parsed.id.should be_nil
      parsed.payload.should be_nil
    end

    it "round-trips envelope with id" do
      env = Envelope.new("fs_reply", "abc123")
      parsed = Envelope.from_json(env.to_json)
      parsed.event.should eq("fs_reply")
      parsed.id.should eq("abc123")
    end

    it "round-trips envelope with payload" do
      payload = JSON::Any.new({"key" => JSON::Any.new("value")})
      env = Envelope.new("test", "id1", payload)
      parsed = Envelope.from_json(env.to_json)
      parsed.event.should eq("test")
      parsed.id.should eq("id1")
      parsed.payload.not_nil!["key"].as_s.should eq("value")
    end

    it "handles nested payload" do
      inner = JSON::Any.new({"nested" => JSON::Any.new("data")})
      payload = JSON::Any.new({"outer" => inner})
      env = Envelope.new("test", payload: payload)
      parsed = Envelope.from_json(env.to_json)
      parsed.payload.not_nil!["outer"]["nested"].as_s.should eq("data")
    end
  end
end

describe Dispatcher do
  it "routes events to registered handlers" do
    d = Dispatcher.new
    received = [] of String

    d.on("ping") { |env| received << "ping:#{env.id}" }
    d.on("pong") { |env| received << "pong:#{env.id}" }

    d.dispatch(Envelope.new("ping", "1").to_json.to_slice)
    d.dispatch(Envelope.new("pong", "2").to_json.to_slice)

    received.should eq(["ping:1", "pong:2"])
  end

  it "calls fallback for unhandled events" do
    d = Dispatcher.new
    unhandled = [] of String
    d.on_unhandled { |env| unhandled << env.event }

    d.dispatch(Envelope.new("unknown").to_json.to_slice)
    unhandled.should eq(["unknown"])
  end

  it "does not call fallback for handled events" do
    d = Dispatcher.new
    handled = false
    fallback = false

    d.on("test") { |_| handled = true }
    d.on_unhandled { |_| fallback = true }

    d.dispatch(Envelope.new("test").to_json.to_slice)
    handled.should be_true
    fallback.should be_false
  end

  it "supports multiple handlers per event" do
    d = Dispatcher.new
    count = 0

    d.on("multi") { |_| count += 1 }
    d.on("multi") { |_| count += 1 }

    d.dispatch(Envelope.new("multi").to_json.to_slice)
    count.should eq(2)
  end

  it "silently ignores invalid JSON" do
    d = Dispatcher.new
    d.dispatch("not json at all".to_slice)
  end
end

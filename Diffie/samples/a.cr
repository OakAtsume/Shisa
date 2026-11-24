#!/bin/crystal


class Dispatcher
  @@table = {} of UInt8 => Proc(Context, Nil)

  def self.register(id : UInt8, &block : Context -> Nil)
    @@table[id] = block
  end

  def self.call(id : UInt8, ctx : Context)
    func = @@table[id]?
    return unless func
    func.call(ctx)
  end
end

class Context
  property stack = [] of (Int32 | String | UInt8 | Int64 )
  property state : UInt8

  def initialize
    @state = 0x42
  end
end

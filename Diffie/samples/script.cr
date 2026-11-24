require "./a.cr"

# ... (Keep your Dispatcher and say method setup here) ...

instruct = [
  {op: :push,       val: "Hello World"},
  {op: :push_int32, val: 1337_i32},
  {op: :push_int64, val: 9223372036854775807_i64}, # Max Int64
  {op: :call,       val: 0x01_u8},
  # {op: :flush,      val: 0x00}
]

# --- 1. SERIALIZE TO A BINARY STRING ---
binary_stream = IO::Memory.new

instruct.each do |ins|
  case ins[:op]
  when :push
    binary_stream.write_byte(1_u8)
    str_bytes = ins[:val].as(String).to_slice
    binary_stream.write_bytes(str_bytes.size.to_u16)
    binary_stream.write(str_bytes)
  when :call
    binary_stream.write_byte(2_u8)
    binary_stream.write_byte(ins[:val].as(UInt8))
  when :flush
    binary_stream.write_byte(3_u8)
  when :push_int32
    binary_stream.write_byte(4_u8)                # Opcode 4
    binary_stream.write_bytes(ins[:val].as(Int32)) # Writes exactly 4 bytes
  when :push_int64
    binary_stream.write_byte(5_u8)                # Opcode 5
    binary_stream.write_bytes(ins[:val].as(Int64)) # Writes exactly 8 bytes
  end
end

bytecode_string = binary_stream.to_s

# --- 2. DESERIALIZE & RUN FROM THE STRING ---
ctx = Context.new
reader = IO::Memory.new(bytecode_string)

# Pro-tip: `reader.bytes_not_read > 0` avoids needing a manual `so_far` counter!

so_far = 0
while so_far <= reader.size
	so_far +=1 
  opcode = reader.read_byte
  
  case opcode
  when 1_u8 # PUSH String
    str_len = reader.read_bytes(UInt16)
    buffer = Bytes.new(str_len)
    reader.read_fully(buffer)
    ctx.stack << String.new(buffer)
  when 2_u8 # CALL
    val = reader.read_byte.not_nil!
    Dispatcher.call(val, ctx)
  when 3_u8 # FLUSH
    ctx.stack.clear
  when 4_u8 # PUSH Int32
    # Crystal automatically reads exactly 4 bytes and builds the Int32
    ctx.stack << reader.read_bytes(Int32)
  when 5_u8 # PUSH Int64
    # Crystal automatically reads exactly 8 bytes and builds the Int64
    ctx.stack << reader.read_bytes(Int64)
  end
end

# Let's inspect the stack at the end to see our integers sitting there safely
p ctx.stack
# Output will show your pushed string (if not popped), the Int32, and the Int64!
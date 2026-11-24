# Dependency-free tests for the portable Diffie library.
#   ruby test.rb
require_relative "diffie"

$failures = 0
def check(name)
  yield
  puts "  ok  #{name}"
rescue => e
  $failures += 1
  puts "  FAIL #{name}: #{e.class}: #{e.message}"
end

def assert(cond, msg = "assertion failed")
  raise msg unless cond
end

# Two sessions handshaken purely by exchanging bytes — no socket.
def handshaken
  alice = Diffie::Session.new(:client)
  bob   = Diffie::Session.new(:server)
  alice.complete_handshake(bob.local_public_key)
  bob.complete_handshake(alice.local_public_key)
  [alice, bob]
end

puts "Diffie::Session"

check "round-trips a message in both directions" do
  alice, bob = handshaken
  assert bob.decrypt(alice.encrypt("hi bob")) == "hi bob"
  assert alice.decrypt(bob.encrypt("hi alice")) == "hi alice"
end

check "exposes a stable 256-byte public key" do
  s = Diffie::Session.new(:client)
  assert s.local_public_key.bytesize == 256
  assert s.local_public_key == s.local_public_key
end

check "rejects a replayed record" do
  alice, bob = handshaken
  record = alice.encrypt("once")
  bob.decrypt(record)
  begin
    bob.decrypt(record); raise "expected ReplayError"
  rescue Diffie::ReplayError
  end
end

check "rejects a tampered record" do
  alice, bob = handshaken
  record = alice.encrypt("tamper me")
  record.setbyte(record.bytesize - 1, record.getbyte(record.bytesize - 1) ^ 0xFF)
  begin
    bob.decrypt(record); raise "expected DecryptError"
  rescue Diffie::DecryptError
  end
end

check "rejects a degenerate peer public key" do
  s = Diffie::Session.new(:client)
  begin
    s.complete_handshake("\x00".b * 256); raise "expected HandshakeError"
  rescue Diffie::HandshakeError
  end
end

check "refuses to encrypt before the handshake" do
  s = Diffie::Session.new(:client)
  begin
    s.encrypt("nope"); raise "expected HandshakeError"
  rescue Diffie::HandshakeError
  end
end

check "round-trips over a Base64 (text) transport" do
  alice, bob = handshaken
  sms = alice.encrypt_to_base64("meet at noon")
  assert sms.match?(/\A[A-Za-z0-9+\/=]+\z/), "not ASCII-safe"
  assert bob.decrypt_from_base64(sms) == "meet at noon"
end

puts "Diffie::Framing"

check "frames and re-parses records over a chunked stream" do
  records = %w[one two three]
  stream = records.map { |r| Diffie::Framing.frame(r) }.join.b
  parser = Diffie::FrameParser.new
  got = []
  stream.each_byte { |byte| parser.feed(byte.chr) { |rec| got << rec } } # one byte at a time
  assert got == records, got.inspect
end

check "raises on an out-of-range length header" do
  parser = Diffie::FrameParser.new
  begin
    parser.feed("\xFF\xFF\xFF\xFF\x00".b) { }; raise "expected Error"
  rescue Diffie::Error
  end
end

puts
if $failures.zero?
  puts "All checks passed."
else
  puts "#{$failures} check(s) failed."
  exit 1
end

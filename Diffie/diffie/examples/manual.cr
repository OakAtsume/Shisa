# Manual, transport-agnostic use of the Diffie protocol — no sockets.
#
# This simulates two people exchanging messages over a channel that only carries
# short text (think SMS): every record is Base64-encoded so it's ASCII-safe, and
# the two sides hand strings back and forth by hand.
#
#   crystal run examples/manual.cr
#
require "../src/session"

# A stand-in for "some text channel" (SMS, a chat box, a QR code on screen…).
# In real life `send` would put the string on the wire; here we just print it
# and return it so the other side can receive it.
def transmit(from : String, text : String) : String
  puts "  #{from} ──SMS──▶ #{text}"
  text
end

alice = Diffie::Session.new(Diffie::Role::Client)
bob = Diffie::Session.new(Diffie::Role::Server)

# ── 1. Exchange public keys (256 bytes each) over any channel ────────────────
# Over SMS you'd Base64 these too; shown as hex here just to keep it short.
puts "Handshake — swap public keys:"
alice_pub = alice.local_public_key
bob_pub = bob.local_public_key
puts "  Alice pub: …#{alice_pub.hexstring[-32..]} (#{alice_pub.size} bytes)"
puts "  Bob   pub: …#{bob_pub.hexstring[-32..]} (#{bob_pub.size} bytes)"

alice.complete_handshake(bob_pub)
bob.complete_handshake(alice_pub)
puts "  ✓ both sides derived directional keys\n\n"

# ── 2. Talk. Each message becomes one Base64 record you can text. ────────────
puts "Alice → Bob:"
sms1 = transmit("Alice", alice.encrypt_to_base64("Meet at the docks, midnight."))
puts "  Bob decrypts: #{String.new(bob.decrypt_from_base64(sms1))}\n\n"

puts "Bob → Alice:"
sms2 = transmit("Bob", bob.encrypt_to_base64("Understood. Bringing the cat."))
puts "  Alice decrypts: #{String.new(alice.decrypt_from_base64(sms2))}\n\n"

# ── 3. The protections still hold off the wire. ──────────────────────────────
puts "Security checks:"
begin
  bob.decrypt_from_base64(sms1) # replay the first SMS
rescue ex : Diffie::ReplayError
  puts "  ✓ replayed SMS rejected (#{ex.message})"
end

tampered = alice.encrypt("secret")
tampered[-1] ^= 0xFF
begin
  bob.decrypt(tampered)
rescue ex : Diffie::DecryptError
  puts "  ✓ tampered record rejected (#{ex.message})"
end

# Manual, transport-agnostic use of the Diffie protocol — no sockets.
#
# Simulates two people exchanging messages over a channel that only carries
# short text (think SMS): every record is Base64-encoded so it's ASCII-safe, and
# the two sides hand strings back and forth by hand.
#
#   ruby example_manual.rb
#
require_relative "diffie"

# A stand-in for "some text channel" (SMS, a chat box, a QR code on screen…).
def transmit(from, text)
  puts "  #{from} --SMS--> #{text}"
  text
end

alice = Diffie::Session.new(:client)
bob   = Diffie::Session.new(:server)

# 1. Exchange public keys (256 bytes each) over any channel ------------------
puts "Handshake -- swap public keys:"
alice_pub = alice.local_public_key
bob_pub   = bob.local_public_key
puts "  Alice pub: ...#{alice_pub.unpack1('H*')[-32..]} (#{alice_pub.bytesize} bytes)"
puts "  Bob   pub: ...#{bob_pub.unpack1('H*')[-32..]} (#{bob_pub.bytesize} bytes)"

alice.complete_handshake(bob_pub)
bob.complete_handshake(alice_pub)
puts "  OK both sides derived directional keys", ""

# 2. Talk. Each message becomes one Base64 record you can text. --------------
puts "Alice -> Bob:"
sms1 = transmit("Alice", alice.encrypt_to_base64("Meet at the docks, midnight."))
puts "  Bob decrypts: #{bob.decrypt_from_base64(sms1)}", ""

puts "Bob -> Alice:"
sms2 = transmit("Bob", bob.encrypt_to_base64("Understood. Bringing the cat."))
puts "  Alice decrypts: #{alice.decrypt_from_base64(sms2)}", ""

# 3. The protections still hold off the wire. --------------------------------
puts "Security checks:"
begin
  bob.decrypt_from_base64(sms1) # replay the first SMS
rescue Diffie::ReplayError => e
  puts "  OK replayed SMS rejected (#{e.message})"
end

tampered = alice.encrypt("secret")
tampered.setbyte(tampered.bytesize - 1, tampered.getbyte(tampered.bytesize - 1) ^ 0xFF)
begin
  bob.decrypt(tampered)
rescue Diffie::DecryptError => e
  puts "  OK tampered record rejected (#{e.message})"
end

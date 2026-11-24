require "./spec_helper"

describe AEAD do
  # Vector produced by Ruby's OpenSSL "chacha20-poly1305" (what the server uses).
  # Locks in wire-compatibility with the reference implementation.
  key   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".hexbytes
  nonce = "0b0a0908070605040302010f".hexbytes
  msg   = "The quick brown fox".to_slice

  it "produces ciphertext/tag identical to OpenSSL" do
    ct, tag = AEAD.seal(key, nonce, msg)
    ct.hexstring.should eq("da4b25b2bd9cae30bf4e472437320a912ea57a")
    tag.hexstring.should eq("0d1a7522cb4817dcdbc7576f531f2144")
  end

  it "decrypts what it encrypts" do
    ct, tag = AEAD.seal(key, nonce, msg)
    AEAD.open(key, nonce, ct, tag).should eq(msg)
  end

  it "rejects a tampered ciphertext" do
    ct, tag = AEAD.seal(key, nonce, msg)
    ct[0] ^= 0xFF
    AEAD.open(key, nonce, ct, tag).should be_nil
  end

  it "rejects a tampered tag" do
    ct, tag = AEAD.seal(key, nonce, msg)
    tag[0] ^= 0xFF
    AEAD.open(key, nonce, ct, tag).should be_nil
  end
end

describe HKDF do
  it "matches RFC 5869 test case 1" do
    ikm  = ("0b" * 22).hexbytes
    salt = "000102030405060708090a0b0c".hexbytes
    info = "f0f1f2f3f4f5f6f7f8f9".hexbytes
    okm = HKDF.derive(ikm, salt, info, 42)
    okm.hexstring.should eq("3cb25f25faacd57a90434f64d0362f2a" \
                            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" \
                            "34007208d5b887185865")
  end

  it "agrees with Ruby OpenSSL::KDF.hkdf for the diffie/v1 context" do
    # Cross-checked against: OpenSSL::KDF.hkdf(ikm, salt:"", info:"diffie/v1",
    #                                          length:64, hash:"SHA256")
    ikm = "00112233445566778899aabbccddeeff0123456789abcdef".hexbytes
    okm = HKDF.derive(ikm, "", "diffie/v1", 64)
    okm.hexstring.should eq("bcff1a4783336ffc069fcf68227a3744" \
                            "10e8a2c77560c2226c4d2cacb453b2ae" \
                            "3a3a47078af973e083b43f24dc6f8826" \
                            "57fb93b9da7a57f00b7dc61971f27887")
  end

  it "splits into two distinct directional keys" do
    okm = HKDF.derive(Bytes.new(32, 7_u8), "", "diffie/v1", 64)
    c2s = okm[0, 32]
    s2c = okm[32, 32]
    c2s.should_not eq(s2c)
  end
end

# Two sessions handshaken purely by exchanging byte strings — no socket involved.
private def handshaken
  alice = Diffie::Session.new(Diffie::Role::Client)
  bob = Diffie::Session.new(Diffie::Role::Server)
  a_pub = alice.local_public_key
  b_pub = bob.local_public_key
  alice.complete_handshake(b_pub)
  bob.complete_handshake(a_pub)
  {alice, bob}
end

describe Diffie::Session do
  it "round-trips a message in both directions" do
    alice, bob = handshaken
    String.new(bob.decrypt(alice.encrypt("hi bob"))).should eq("hi bob")
    String.new(alice.decrypt(bob.encrypt("hi alice"))).should eq("hi alice")
  end

  it "exposes a stable 256-byte public key" do
    s = Diffie::Session.new(Diffie::Role::Client)
    s.local_public_key.size.should eq(256)
    s.local_public_key.should eq(s.local_public_key)
  end

  it "rejects a replayed record" do
    alice, bob = handshaken
    record = alice.encrypt("once")
    bob.decrypt(record)
    expect_raises(Diffie::ReplayError) { bob.decrypt(record) }
  end

  it "rejects a tampered record" do
    alice, bob = handshaken
    record = alice.encrypt("tamper me")
    record[-1] ^= 0xFF
    expect_raises(Diffie::DecryptError) { bob.decrypt(record) }
  end

  it "rejects a degenerate peer public key" do
    s = Diffie::Session.new(Diffie::Role::Client)
    expect_raises(Diffie::HandshakeError) { s.complete_handshake(Bytes.new(256, 0_u8)) }
  end

  it "refuses to encrypt before the handshake" do
    s = Diffie::Session.new(Diffie::Role::Client)
    expect_raises(Diffie::HandshakeError) { s.encrypt("nope") }
  end

  it "round-trips over a text (Base64) transport" do
    alice, bob = handshaken
    sms = alice.encrypt_to_base64("meet at noon")
    sms.should match(/\A[A-Za-z0-9+\/=]+\z/) # plain ASCII, SMS-safe
    String.new(bob.decrypt_from_base64(sms)).should eq("meet at noon")
  end
end

describe Diffie::Framing do
  it "frames and re-parses records over a chunked stream" do
    records = ["one", "two", "three"].map(&.to_slice)
    stream = IO::Memory.new
    records.each { |r| stream.write(Diffie::Framing.frame(r)) }

    parser = Diffie::FrameParser.new
    got = [] of String
    bytes = stream.to_slice
    # Feed the stream one byte at a time to prove boundary handling.
    bytes.size.times { |i| parser.feed(bytes[i, 1]) { |rec| got << String.new(rec) } }
    got.should eq(["one", "two", "three"])
  end

  it "raises on an out-of-range length header" do
    parser = Diffie::FrameParser.new
    bogus = Bytes[0xFF, 0xFF, 0xFF, 0xFF, 0x00]
    expect_raises(Diffie::Error) { parser.feed(bogus) { } }
  end
end

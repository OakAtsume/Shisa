require "big"

def powmod(b : BigInt, x : BigInt, m : BigInt) : BigInt
  r = 1.to_big_i; b = b.to_big_i;
  while x > 0
    r = (r * b) % m if x.odd?()
    b = (b * b) % m
    x >>= 1
  end
  return r
end


hex_prime = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD29024E088A67CC74020BBEA63B139B22514A08798E3404DDE485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
prime = BigInt.new(hex_prime, 16)
gen = BigInt.new(2)

# Use the SAME fixed number
privKey = BigInt.new("123456789", 10)
# puts gen.to_big_i.powmod(privKey, prime)
puts powmod(gen, privKey, prime)
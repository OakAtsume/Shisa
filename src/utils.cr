#!/bin/crystal

#######################################################
# Obfuscation Engine and VM Dispatcher. 							#
# Malware Development and Research for the Motherland #
#######################################################

require "big" # Import BigInt lib (required)

def bytexor(a : UInt8, b : UInt8) : UInt8
	a ^ b
end

def xor(data : Bytes, key : Bytes) : Bytes
	output = Bytes.new(data.bytesize)
	
	data.each_with_index do |byte, index|
		output[i] = byte ^ key[index % key.size]
	end
	data = nil
	key = nil
	output
end


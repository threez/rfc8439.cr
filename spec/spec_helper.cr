require "spec"
require "../src/rfc8439"

def only_hex(input : String) : String
  input.gsub(/[^a-fA-F0-9]/, "")
end

def to_hex(block : StaticArray(UInt32, 16)) : String
  to_hex(Crypto::ChaCha20.block_bytes(block))
end

def to_hex(raw) : String
  raw.reduce("") do |acc, byte|
    acc + byte.to_s(16).rjust(2, '0')
  end
end

def parse_hex(input : String) : Bytes
  bytes = only_hex(input).hexbytes
  Bytes.new(bytes.size) { |i| bytes[i] }
end

require "spec"
require "../src/rfc8439"

def only_hex(input : String) : String
  input.gsub(/[^a-fA-F0-9]/, "")
end

def to_hex(block : StaticArray(UInt32, 16)) : String
  str = ""
  16.times do |i|
    str += block[i].to_s(16).rjust(8, '0')
  end
  str
end

def to_hex(raw) : String
  str = ""
  raw.each do |byte|
    str += byte.to_s(16).rjust(2, '0')
  end
  str
end

def parse_hex(input : String) : Bytes
  hex_str = only_hex(input)
  bytes = hex_str.hexbytes
  Bytes.new(bytes.size) { |i| bytes[i] }
end

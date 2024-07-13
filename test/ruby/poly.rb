
CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffff

def le_bytes_to_num(buf)
  buf.each.with_index.reduce(0) do |acc, (byte, index)|
    acc + (byte << (index * 8))
  end
end

def num_to_le_bytes(num)
  buf = []
  while num > 0
    buf << (num & 0xFF)
    num >>= 8
  end
  buf.pack('C*')
end

def poly1305_mac(msg, key)
  r = le_bytes_to_num(key[0...16])
  r &= CLAMP
  s = le_bytes_to_num(key[16...32])
  a = 0 # accumulator
  p = (2**130)-5  
  rounds = (msg.size.to_f / 16).ceil
  rounds.times do |i|
    n = le_bytes_to_num(msg[(i*16)...((i+1)*16)] + [0x01])
    a += n
    a = (r * a) % p
  end
  a += s
  num_to_le_bytes(a)[0...16]
end


key_hex = "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:"+
  "01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b"
key = [key_hex.gsub(":", "")].pack("H*")

msg = "Cryptographic Forum Research Group"

tag = poly1305_mac(msg.bytes, key.bytes)
puts tag.unpack("H*")


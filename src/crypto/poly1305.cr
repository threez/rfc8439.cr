require "big"
require "./chacha20"

# Poly1305 message authentication code.
class Crypto::Poly1305
  # :nodoc:
  BLOCK_SIZE = 16
  # :nodoc:
  CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffff_u128
  # :nodoc:
  P = (BigInt.new(2) &** 130) &- 5
  # :nodoc:
  EB = BigInt.new(0x01_u8) << 16 * 8

  @r : BigInt
  @a : BigInt
  @s : BigInt

  getter key : Bytes

  # Generating the Poly1305 Key Using ChaCha20
  def self.chacha20(key : Bytes, nonce : Bytes) : Poly1305
    chacha20(ChaCha20.new(key, nonce))
  end

  # Generating the Poly1305 Key Using ChaCha20
  def self.chacha20(cipher : ChaCha20) : Poly1305
    block = ChaCha20.block_bytes(cipher.clone.next_key_block, false)
    new(block[0..31])
  end

  # Initializes the Poly1305 context with a given 32-byte key.
  # The key should be used only once per message and then discarded.
  def initialize(@key : Bytes)
    raise "key needs to be 256 bits (32 bytes)" if @key.size != 32
    @r = le_bytes_to_num(key[0..16], 0)
    @r &= CLAMP
    @s = le_bytes_to_num(key[16..31], 0)
    @a = BigInt.new # accumulator
  end

  # Initializes the Poly1305 context with a given 32-byte **hex-encoded** key.
  # The key should be used only once per message and then discarded.
  def initialize(key : String)
    initialize(Crypto::Hex.bytes(key))
  end

  # Processes a message fragment, msg bytes should be 16 bytes alligned
  # if different size is used the final block is assumed, further
  # calculations would be incorrect
  def update(msg : Bytes)
    msg_end = msg.size &- 1
    rounds = (msg.size.to_f / 16).ceil.to_i
    rounds.times do |i|
      low = i &* 16
      high = (i &+ 1) &* 16 &- 1

      if high < msg_end
        n = le_bytes_to_num17(msg[low..high])
      else
        high = msg_end
        n = le_bytes_to_num(msg[low..high], 0x01_u8)
      end

      @a &+= n
      @a = (@r &* @a) % P
    end
  end

  # Finalizes the MAC computation and returns the 16-byte authenticator.
  def final : Bytes
    @a += @s
    num_to_le_bytes(@a)
  end

  # A convenience method to compute a Poly1305 MAC for a single message.
  def self.auth(key : Bytes, message : Bytes) : Bytes
    pa = new(key)
    pa.update(message)
    pa.final
  end

  # le_bytes_to_num17 is the hot path in the #update method
  # and optimized to reduce the number of big int operations
  private def le_bytes_to_num17(buf : Bytes) : BigInt
    acc1 = 0_u64
    {% for i in 0..8 %}
    acc1 &+= buf.to_unsafe[{{i}}].to_u64 << {{i * 8}}
    {% end %}

    acc2 = 0_u64
    {% for i in 8..15 %}
    acc2 &+= buf.to_unsafe[{{i}}].to_u64 << {{(i - 8) * 8}}
    {% end %}

    acc = EB &+ acc1
    acc &+= BigInt.new(acc2) << {{8*8}}
    acc
  end

  private def le_bytes_to_num(buf : Bytes, extra_byte : UInt8) : BigInt
    acc = BigInt.new(0)
    buf.each_with_index do |byte, index|
      acc &+= BigInt.new(byte) << (index &* 8)
    end
    if extra_byte
      acc &+= BigInt.new(extra_byte) << (buf.size &* 8)
    end
    acc
  end

  private def num_to_le_bytes(num : BigInt)
    Bytes.new(BLOCK_SIZE) do
      if num > 0
        v = (num & 0xFF_u8).to_u8
        num >>= 8
        v
      else
        0_u8
      end
    end
  end
end

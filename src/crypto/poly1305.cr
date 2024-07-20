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
    @r = BigInt.new(IO::ByteFormat::LittleEndian.decode(UInt128, key[0..16]))
    @r &= CLAMP
    @s = BigInt.new(IO::ByteFormat::LittleEndian.decode(UInt128, key[16..31]))
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
    rounds = msg.size // BLOCK_SIZE

    # all aligned rounds
    rounds.times do |i|
      n = IO::ByteFormat::LittleEndian.decode(UInt128,
        msg[(i &* BLOCK_SIZE)...((i &+ 1) &* BLOCK_SIZE)])
      @a &+= EB &+ n
      @a = (@r &* @a) % P
    end

    # final round
    if msg.size % BLOCK_SIZE != 0
      n = le_bytes_to_num(msg[(rounds &* BLOCK_SIZE)...(msg.size)], 0x01_u8)
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

require "big"
require "./chacha20"

module Crypto
  class Poly1305
    # :nodoc:
    BLOCK_SIZE = 16
    # :nodoc:
    CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffff_u128
    # :nodoc:
    P = (BigInt.new(2) ** 130) - 5

    @r : BigInt
    @a : BigInt
    @s : BigInt

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
    def initialize(@key : String)
      initialize(Crypto::Hex.bytes(key))
    end

    # Processes a message fragment, msg bytes should be 16 bytes alligned
    # if different size is used the final block is assumed, further
    # calculations would be incorrect
    def update(msg : Bytes)
      rounds = (msg.size.to_f / 16).ceil.to_i
      rounds.times do |i|
        low = i * 16
        high = [(i + 1)*16 - 1, msg.size - 1].min

        n = le_bytes_to_num(msg[low..high], 0x01_u8)
        @a += n
        @a = (@r * @a) % P
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
        acc += BigInt.new(byte) << (index * 8)
      end
      if extra_byte
        acc += BigInt.new(extra_byte) << (buf.size * 8)
      end
      acc
    end

    private def num_to_le_bytes(num : BigInt)
      buf = Array(UInt8).new

      while num > 0
        buf << (num & 0xFF_u64).to_u8
        num >>= 8
      end

      Bytes.new(BLOCK_SIZE) do |i|
        buf[i]
      end
    end
  end
end

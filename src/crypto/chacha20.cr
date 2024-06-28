module Crypto
  alias WordBlock = StaticArray(UInt32, 16)

  # The ChaCha20 cipheris a high-speed cipher
  # It is considerably faster than AES in software-only
  # implementations, making it around three times as fast on
  # platforms that lack specialized AES hardware.
  # ChaCha20 is also not sensitive to timing attacks.
  class ChaCha20
    getter block_state : Array(UInt32)

    def initialize(key : String, nonce : String, counter : UInt32 = 0_u32)
      key = Crypto.only_hex(key).hexbytes
      nonce = Crypto.only_hex(nonce).hexbytes
      initialize(key, nonce, counter)
    end

    # The inputs to ChaCha20 are:
    # * key: A 256-bit key, treated as a concatenation of eight 32-bit little-
    #   endian integers.
    # * nonce: A 96-bit nonce, treated as a concatenation of three 32-bit little-
    #   endian integers.
    # * counter: A 32-bit block count parameter, treated as a 32-bit little-endian
    #   integer.
    def initialize(key : Bytes, nonce : Bytes, counter : UInt32 = 0_u32)
      @state = WordBlock.new(0_u32)
      @block_state = Array(UInt32).new(16) { 0_u32 }

      i = -1

      # Constants
      @state[i += 1] = 0x61707865
      @state[i += 1] = 0x3320646e
      @state[i += 1] = 0x79622d32
      @state[i += 1] = 0x6b206574

      # Key
      @state[i += 1] = IO::ByteFormat::LittleEndian.decode(UInt32, key[0, 4])
      @state[i += 1] = IO::ByteFormat::LittleEndian.decode(UInt32, key[4, 4])
      @state[i += 1] = IO::ByteFormat::LittleEndian.decode(UInt32, key[8, 4])
      @state[i += 1] = IO::ByteFormat::LittleEndian.decode(UInt32, key[12, 4])
      @state[i += 1] = IO::ByteFormat::LittleEndian.decode(UInt32, key[16, 4])
      @state[i += 1] = IO::ByteFormat::LittleEndian.decode(UInt32, key[20, 4])
      @state[i += 1] = IO::ByteFormat::LittleEndian.decode(UInt32, key[24, 4])
      @state[i += 1] = IO::ByteFormat::LittleEndian.decode(UInt32, key[28, 4])

      # Counter
      @state[i += 1] = counter

      # Nonce
      @state[i += 1] = IO::ByteFormat::LittleEndian.decode(UInt32, nonce[0, 4])
      @state[i += 1] = IO::ByteFormat::LittleEndian.decode(UInt32, nonce[4, 4])
      @state[i += 1] = IO::ByteFormat::LittleEndian.decode(UInt32, nonce[8, 4])
    end

    def encrypt(plaintext : String)
      encrypt(Text.new(plaintext))
    end

    def encrypt(plaintext : Text)
      encrypted = Text.new(plaintext.size)
      plaintext.each_block(64) do |plaintext_block|
        key_block = next_key_block
        16.times do |i|
          plaintext_block[i*4] ^= (key_block[i] >> 0 * 8) & 0xff_u8
          plaintext_block[i*4 + 1] ^= (key_block[i] >> 1 * 8) & 0xff_u8
          plaintext_block[i*4 + 2] ^= (key_block[i] >> 2 * 8) & 0xff_u8
          plaintext_block[i*4 + 3] ^= (key_block[i] >> 3 * 8) & 0xff_u8
        end
        encrypted << plaintext_block
      end
      encrypted
    end

    # reads from plaintext and writes to encrypted
    def encrypt(plaintext : IO, encrypted : IO)
      slice = Bytes.new(64)
      loop do
        n = plaintext.read(slice)
        break if n == 0
        plaintext_block = Text.new(slice)
        plaintext_block.xor(next_key_block)
        encrypted.write(plaintext_block.raw[0, n])
      end
    end

    def decrypt(ciphertext : Text)
      encrypt(ciphertext)
    end

    def next_key_block
      # initialize block state
      @state.each_with_index do |byte, i|
        @block_state[i] = byte
      end

      # perform inner blocks 10 times
      10.times do
        quarter_round(@block_state, 0, 4, 8, 12)
        quarter_round(@block_state, 1, 5, 9, 13)
        quarter_round(@block_state, 2, 6, 10, 14)
        quarter_round(@block_state, 3, 7, 11, 15)
        quarter_round(@block_state, 0, 5, 10, 15)
        quarter_round(@block_state, 1, 6, 11, 12)
        quarter_round(@block_state, 2, 7, 8, 13)
        quarter_round(@block_state, 3, 4, 9, 14)
      end

      @block_state.size.times do |i|
        @block_state[i] &+= @state[i]
      end

      # increment block counter
      @state[12] += 1

      @block_state
    end

    macro quarter_round(state, a, b, c, d)
      {{state}}[{{a}}] &+= {{state}}[{{b}}]
      {{state}}[{{d}}] =  ({{state}}[{{d}}] ^ {{state}}[{{a}}]).rotl(16)
      {{state}}[{{c}}] &+= {{state}}[{{d}}]
      {{state}}[{{b}}] =  ({{state}}[{{b}}] ^ {{state}}[{{c}}]).rotl(12)
      {{state}}[{{a}}] &+= {{state}}[{{b}}]
      {{state}}[{{d}}] =  ({{state}}[{{d}}] ^ {{state}}[{{a}}]).rotl(8)
      {{state}}[{{c}}] &+= {{state}}[{{d}}]
      {{state}}[{{b}}] =  ({{state}}[{{b}}] ^ {{state}}[{{c}}]).rotl(7)
    end

    def to_hex : String
      str = ""
      16.times do |i|
        str += @block_state[i].to_s(16).rjust(8, '0')
      end
      str
    end
  end
end

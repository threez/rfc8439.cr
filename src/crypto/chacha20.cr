module Crypto
  alias WordBlock = StaticArray(UInt32, 16)

  # The ChaCha20 cipheris a high-speed cipher
  # It is considerably faster than AES in software-only
  # implementations, making it around three times as fast on
  # platforms that lack specialized AES hardware.
  # ChaCha20 is also not sensitive to timing attacks.
  class ChaCha20
    BLOCK_SIZE = 64

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

    def encrypt(plaintext : Bytes) : Bytes
      encrypted = Bytes.new(plaintext.size + plaintext.size % BLOCK_SIZE)
      encrypt(plaintext, encrypted)
      encrypted[0, plaintext.size]
    end

    def encrypt(plaintext : Bytes, encrypted : Bytes) : Nil
      # if (encrypted.size % BLOCK_SIZE) != 0
      #   raise "encrypted needs to be multiple of #{BLOCK_SIZE} but is #{encrypted.size}"
      # end

      block_state = WordBlock.new(0u32)
      Intrinsics.memcpy(encrypted.to_unsafe, plaintext.to_unsafe, plaintext.size, false)

      (encrypted.size // BLOCK_SIZE).times do |pos|
        key_block = next_key_block(block_state)
        16.times do |i|
          encrypted[pos*BLOCK_SIZE + i*4] ^= (key_block[i] >> 0 * 8) & 0xff_u8
          encrypted[pos*BLOCK_SIZE + i*4 + 1] ^= (key_block[i] >> 1 * 8) & 0xff_u8
          encrypted[pos*BLOCK_SIZE + i*4 + 2] ^= (key_block[i] >> 2 * 8) & 0xff_u8
          encrypted[pos*BLOCK_SIZE + i*4 + 3] ^= (key_block[i] >> 3 * 8) & 0xff_u8
        end
      end
    end

    # reads from plaintext and writes to encrypted
    def encrypt(plaintext : IO, encrypted : IO)
      plaintext_block = Bytes.new(BLOCK_SIZE)
      encrypted_block = Bytes.new(BLOCK_SIZE)
      loop do
        n = plaintext.read(plaintext_block)
        break if n == 0
        encrypt(plaintext_block, encrypted_block)
        encrypted.write(encrypted_block.raw[0, n])
      end
    end

    def next_key_block(block_state : WordBlock) : WordBlock
      # initialize block state
      Intrinsics.memcpy(block_state.to_unsafe, @state.to_unsafe, BLOCK_SIZE, false)

      # perform inner blocks 10 times
      10.times do
        quarter_round(block_state, 0, 4, 8, 12)
        quarter_round(block_state, 1, 5, 9, 13)
        quarter_round(block_state, 2, 6, 10, 14)
        quarter_round(block_state, 3, 7, 11, 15)
        quarter_round(block_state, 0, 5, 10, 15)
        quarter_round(block_state, 1, 6, 11, 12)
        quarter_round(block_state, 2, 7, 8, 13)
        quarter_round(block_state, 3, 4, 9, 14)
      end

      # apply state to block state
      16.times do |i|
        block_state[i] &+= @state[i]
      end

      # increment block counter
      @state[12] += 1

      block_state
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
  end
end

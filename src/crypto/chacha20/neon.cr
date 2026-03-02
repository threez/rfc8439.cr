{% if flag?(:aarch64) %}
  @[Link(ldflags: "#{__DIR__}/../../../ext/chacha20_neon.o")]
  lib LibChaCha20NEON
    fun chacha20_neon_encrypt(state : UInt32*, out : UInt8*, inp : UInt8*, len : LibC::SizeT)
  end

  # NEON-accelerated ChaCha20 backend for aarch64.
  # Inherits from Native and overrides the two-arg encrypt method
  # to use ARM NEON SIMD for 4-block (256-byte) chunks.
  class Crypto::ChaCha20::Neon < Crypto::ChaCha20::Native
    # reads from plaintext and writes to encrypted
    def encrypt(plaintext : Bytes, encrypted : Bytes) : Nil
      raise "encrypted needs to be multiple of #{BLOCK_SIZE}" unless encrypted.size % BLOCK_SIZE == 0

      total_blocks = encrypted.size // BLOCK_SIZE

      neon_blocks = (total_blocks // 4) &* 4
      neon_bytes = neon_blocks &* BLOCK_SIZE

      if neon_bytes > 0
        LibChaCha20NEON.chacha20_neon_encrypt(
          @state.to_unsafe,
          encrypted.to_unsafe,
          plaintext.to_unsafe,
          neon_bytes)
        @state[12] &+= neon_blocks.to_u32
      end

      # Scalar fallback for remaining 0-3 blocks
      if neon_blocks < total_blocks
        full_plain_blocks = plaintext.size // BLOCK_SIZE
        block_state = uninitialized UInt32[16]
        block_ptr = block_state.to_unsafe
        state_ptr = @state.to_unsafe
        enc_base = encrypted.to_unsafe
        plain_base = plaintext.to_unsafe

        # Full blocks from plaintext: direct read + combined add/XOR
        start_block = neon_blocks
        end_full = Math.min(full_plain_blocks, total_blocks)
        (start_block...end_full).each do |pos|
          block_ptr.copy_from(state_ptr, 16)
          10.times do
            quarter_round(block_ptr, 0, 4, 8, 12)
            quarter_round(block_ptr, 1, 5, 9, 13)
            quarter_round(block_ptr, 2, 6, 10, 14)
            quarter_round(block_ptr, 3, 7, 11, 15)
            quarter_round(block_ptr, 0, 5, 10, 15)
            quarter_round(block_ptr, 1, 6, 11, 12)
            quarter_round(block_ptr, 2, 7, 8, 13)
            quarter_round(block_ptr, 3, 4, 9, 14)
          end

          enc_ptr = (enc_base + pos &* BLOCK_SIZE).as(UInt32*)
          plain_ptr = (plain_base + pos &* BLOCK_SIZE).as(UInt32*)
          16.times do |i|
            enc_ptr[i] = plain_ptr[i] ^ (block_ptr[i] &+ state_ptr[i])
          end

          state_ptr[12] &+= 1
          raise "counter overflow, more then 256 GB encrypted" if state_ptr[12] == 0
        end

        # Remaining blocks (partial last block + any padding blocks)
        (end_full...total_blocks).each do |pos|
          byte_offset = pos &* BLOCK_SIZE
          enc_slice = encrypted[byte_offset, BLOCK_SIZE]
          remaining = plaintext.size - byte_offset
          if remaining > 0
            enc_slice.copy_from(plaintext[byte_offset, remaining])
            enc_slice[remaining..].fill(0_u8)
          else
            enc_slice.fill(0_u8)
          end

          block_ptr.copy_from(state_ptr, 16)
          10.times do
            quarter_round(block_ptr, 0, 4, 8, 12)
            quarter_round(block_ptr, 1, 5, 9, 13)
            quarter_round(block_ptr, 2, 6, 10, 14)
            quarter_round(block_ptr, 3, 7, 11, 15)
            quarter_round(block_ptr, 0, 5, 10, 15)
            quarter_round(block_ptr, 1, 6, 11, 12)
            quarter_round(block_ptr, 2, 7, 8, 13)
            quarter_round(block_ptr, 3, 4, 9, 14)
          end

          enc_ptr = (enc_base + byte_offset).as(UInt32*)
          16.times do |i|
            enc_ptr[i] ^= (block_ptr[i] &+ state_ptr[i])
          end

          state_ptr[12] &+= 1
          raise "counter overflow, more then 256 GB encrypted" if state_ptr[12] == 0
        end
      end
    end
  end
{% end %}

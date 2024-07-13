require "./spec_helper"

describe Crypto::Hex do
  it "bytes" do
    Crypto::Hex.bytes("85:d6:be").should eq(Bytes[0x85, 0xd6, 0xbe])
    Crypto::Hex.bytes("43 72 79").should eq(Bytes[0x43, 0x72, 0x79])
  end
end

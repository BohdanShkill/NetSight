#include <gtest/gtest.h>
#include <cstddef>                  
#include <cstdint>                  
#include <vector>                   
#include "netsight/core/ByteReader.hpp"
#include "netsight/core/Types.hpp"

using namespace netsight;

TEST(ByteReaderTest, ReadsBigAndLittleEndian) {
    std::vector<Byte> data = {0x12, 0x34, 0x56, 0x78};

    ByteReader r_be16(data);
    EXPECT_EQ(r_be16.u16_be(), 0x1234);
    EXPECT_EQ(r_be16.u16_be(), 0x5678);

    ByteReader r_le16(data);
    EXPECT_EQ(r_le16.u16_le(), 0x3412);
    EXPECT_EQ(r_le16.u16_le(), 0x7856);

    ByteReader r_be32(data);
    EXPECT_EQ(r_be32.u32_be(), 0x12345678);

    ByteReader r_le32(data);
    EXPECT_EQ(r_le32.u32_le(), 0x78563412);
}

TEST(ByteReaderTest, PositionAndRemainingAdvance) {
    std::vector<Byte> data = {0x12, 0x34, 0x56, 0x78};
    ByteReader reader(data);

    EXPECT_TRUE(reader.ok());
    EXPECT_EQ(reader.position(), 0u);
    EXPECT_EQ(reader.remaining(), 4u);

    reader.u16_be();
    EXPECT_EQ(reader.position(), 2u);
    EXPECT_EQ(reader.remaining(), 2u);
}

TEST(ByteReaderTest, ShortReadFailsWithoutAdvancing) {
    std::vector<Byte> data = {0x12, 0x34, 0x56};
    ByteReader reader(data);

    EXPECT_TRUE(reader.ok());
    EXPECT_EQ(reader.position(), 0u);
    EXPECT_EQ(reader.remaining(), 3u);

    reader.u32_be(); 
    EXPECT_FALSE(reader.ok());
    EXPECT_EQ(reader.position(), 0u); 
    EXPECT_EQ(reader.remaining(), 3u);
}

TEST(ByteReaderTest, FailureIsSticky) {
    std::vector<Byte> data = {0x12, 0x34, 0x56};
    ByteReader reader(data);

    EXPECT_EQ(reader.u32_be(), 0u);
    EXPECT_FALSE(reader.ok());
    EXPECT_EQ(reader.position(), 0u);

    EXPECT_EQ(reader.u8(), 0u);
    EXPECT_FALSE(reader.ok());
    EXPECT_EQ(reader.position(), 0u);
}

TEST(ByteReaderTest, SkipBeyondEndFails) {
    std::vector<Byte> data = {0x12, 0x34, 0x56};
    ByteReader reader(data);

    EXPECT_TRUE(reader.ok());
    reader.skip(10); 
    EXPECT_FALSE(reader.ok());
    EXPECT_EQ(reader.position(), 0u);
}

TEST(ByteReaderTest, BytesReturnsViewIntoBuffer) {
    std::vector<Byte> data = {0x12, 0x34, 0x56, 0x78};
    ByteReader reader(data);

    EXPECT_TRUE(reader.ok());
    const Byte* ptr = reader.bytes(2);
    EXPECT_TRUE(reader.ok());
    EXPECT_EQ(ptr[0], 0x12);
    EXPECT_EQ(ptr[1], 0x34);
    EXPECT_EQ(reader.position(), 2u);
}

TEST(ByteReaderTest, HugeLengthDoesNotOverflow){
    std::vector<Byte> data = {0x12, 0x34, 0x56, 0x78};
    ByteReader reader(data);

    EXPECT_TRUE(reader.ok());
    reader.skip(SIZE_MAX); 
    EXPECT_FALSE(reader.ok());
    EXPECT_EQ(reader.position(), 0u);
}

TEST(ByteReaderTest, NullPointerIsEmpty){
    ByteReader reader(nullptr, 100);
    EXPECT_EQ(reader.position(), 0u);
    EXPECT_EQ(reader.remaining(), 0u);

    EXPECT_EQ(reader.u8(), 0u);
    EXPECT_FALSE(reader.ok());
}
#include "md5.h"

#include <gtest/gtest.h>

#include <sstream>
#include <string>

class RFC1321TestVectors : public ::testing::Test {};

void RunTest(const std::string& input, const std::string& expected_hash) {
  // 1. Test the memory-based API
  const std::string hash_mem = md5_lib::calculate_md5(
      reinterpret_cast<const unsigned char*>(input.data()), input.size());
  EXPECT_EQ(hash_mem, expected_hash);

  // 2. Test the stream-based API
  std::stringstream ss(input);
  const std::string hash_stream = md5_lib::calculate_md5(ss);
  EXPECT_EQ(hash_stream, expected_hash);
}

TEST_F(RFC1321TestVectors, EmptyString) {
  RunTest("", "d41d8cd98f00b204e9800998ecf8427e");
}

TEST_F(RFC1321TestVectors, a) {
  RunTest("a", "0cc175b9c0f1b6a831c399e269772661");
}

TEST_F(RFC1321TestVectors, abc) {
  RunTest("abc", "900150983cd24fb0d6963f7d28e17f72");
}

TEST_F(RFC1321TestVectors, MessageDigest) {
  RunTest("message digest", "f96b697d7cb7938d525a2f31aaf161d0");
}

TEST_F(RFC1321TestVectors, LowercaseAlphabet) {
  RunTest("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b");
}

TEST_F(RFC1321TestVectors, Alphanumeric) {
  RunTest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
          "d174ab98d277d9f5a5611c2c9f419d9f");
}

TEST_F(RFC1321TestVectors, LongStringOfNumbers) {
  RunTest(
      "123456789012345678901234567890123456789012345678901234567890123456789012"
      "34567890",
      "57edf4a22be3c955ac49da2e2107b67a");
}